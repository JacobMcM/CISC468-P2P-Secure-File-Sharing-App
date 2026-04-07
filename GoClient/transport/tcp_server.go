package transport

import (
	"GoClient/auth"
	"GoClient/consent"
	"GoClient/crypto"
	"GoClient/discovery"
	file "GoClient/file_manager"
	"GoClient/protocol"
	"GoClient/session"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
)

func StartTCPServer(port int) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	log.Println("TCP server listening on port", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}
		fmt.Printf("NEW CONN")
		go func() {
    		if err := handleConnection(conn); err != nil {
        	log.Println("connection error:", err)
    	}
}()

	}
}

func handleConnection(conn net.Conn) error {
	framed := session.NewFramedConn(conn)

	raw, err := framed.Recv()
	// fmt.Printf("RECEIVED: %s")
	if err != nil {
		// log.Println("Failed to receive initial message from:", framed.RemoteAddr())
		return err
	}

	var base protocol.BaseMessage
	if err := json.Unmarshal(raw, &base); err != nil {
		// log.Println("Failed to parse initial JSON message from:", framed.RemoteAddr())
	}

	switch base.Type {
	case protocol.EKE_1:
		fmt.Printf("EKE1 received")
		parsed, err := protocol.ParseMessage[protocol.EKE1Message](raw); if err != nil {
			// log.Println("Failed to parse EKE1 message")
			return err
		}

		w := "JacobLiam"
		if parsed.From != "JacobPC" {
			w = "CamLiam"
		}

		secureSession, err := auth.RunServerSideDhEKE(framed, parsed, w, "Liam-PC"); if err != nil {
			return err
		}
		go RunSecureServerSession(secureSession)
	case protocol.STS_1:
		fmt.Printf("\n\n\nSTS Received\n\n\n")
		parsed, err := protocol.ParseMessage[protocol.STS1Message](raw); if err != nil {
			return err
		}

		secureSession, err := auth.RunServerSideSTS(framed, parsed, "Liam-PC"); if err != nil {
			return err
		}
		go RunSecureServerSession(secureSession)

	}
	return nil
}

func RunSecureServerSession(session *session.SecureSession) {
	defer session.Close()
    for {
        msgRaw, err := session.Recv()
        if err != nil {
            log.Println("Connection Terminated")
            return
        }

		baseMessage, err := protocol.ParseMessage[protocol.BaseMessage](msgRaw); if err != nil {
			fmt.Printf("Invalid message received: %s", baseMessage)
		}

        switch baseMessage.Type {
        case protocol.FILE_LIST_REQUEST:
			myFileList, err := file.LoadFileList("files/file_list.json"); if err != nil {
				fmt.Println("could not load file list")
			}
			fileListResponse, _ := protocol.BuildFileListResponse(session.SelfName, myFileList)
			session.Send(fileListResponse)
        case protocol.FILE_REQUEST:
			myFileList, err := file.LoadFileList("files/file_list.json"); if err != nil {
				fmt.Println("could not load file list")
			}

			fileRequestMessage, err := protocol.ParseMessage[protocol.FileRequestMessage](msgRaw)
			requestedFile := fileRequestMessage.Filename
			var fileInfo *file.FileInfo
			for _, file := range myFileList {
				if file.Name == requestedFile {
					fileInfo = file
				}
			}

			if fileInfo == nil {
				errMsg, _ := protocol.BuildErrorMessage(session.SelfName, "Could not find requested file")
				session.Send(errMsg)
				continue
			}

			path := "files/" + requestedFile
			data, err := os.ReadFile(path)

			fileTransferMessage, err := protocol.BuildFileTransfer(session.SelfName, fileInfo.Name, fileInfo.OriginalOwner, fileInfo.Hash, fileInfo.Signature, data); if err != nil {
				errMsg, _ := protocol.BuildErrorMessage(session.SelfName, "Could not build fileTransfer message")
				session.Send(errMsg)
				continue
			}
			session.Send(fileTransferMessage)
        case protocol.CONSENT_REQUEST:
			consentMessage, _ := protocol.ParseMessage[protocol.ConsentRequestMessage](msgRaw)
			accepted := consent.Request(fmt.Sprintf("Peer %s wants to send you %s (%d bytes)", consentMessage.From, consentMessage.Filename, consentMessage.Filesize))

			protocol.BuildConsentResponse(session.SelfName, consentMessage.Filename, accepted)

			if !accepted {
				continue
			}

			// wait for file transfer
			resRaw, err := session.Recv(); if err != nil {
				fmt.Println("Error, could not recv response")
				continue
			}

			resBaseMessage, _ := protocol.ParseMessage[protocol.BaseMessage](resRaw)
			switch resBaseMessage.Type {
			case protocol.ERROR_MSG:
				errorMsg, _ := protocol.ParseMessage[protocol.ErrorMessage](resRaw)
				fmt.Println("Peer error ):")
				fmt.Printf("Err: %s", errorMsg.Message)
				continue
			case protocol.FILE_TRANSFER:
				fileTransferMessage, _ := protocol.ParseMessage[protocol.FileTransferMessage](resRaw)
				fmt.Printf("Received file: %s\n", fileTransferMessage.Filename)

				originalOwner := fileTransferMessage.OriginalOwner
				if fileTransferMessage.OriginalOwner == "" {
					originalOwner = fileTransferMessage.From
				}

				fmt.Printf("Original owner: %s", originalOwner)

				// perform sig verification
				peerPubKeys, err := discovery.LoadPeerKeys("keys/peer_pub_keys.json"); if err != nil {
					fmt.Println("Error loading public key ring. Could not verify file signature. File will be discarded")
					continue
				}

				correspondingPubKey := peerPubKeys[originalOwner]
				fmt.Printf("Verifying signature using %s's public key", originalOwner)

				err = crypto.RsaPssVerify(correspondingPubKey, fileTransferMessage.Data, fileTransferMessage.Signature); if err != nil {
					fmt.Println("[Security] File signature verification failed! File will be discarded.")
					continue
				}

				fmt.Println("VERIFICATION SUCCESS")
				path := "files/" + fileTransferMessage.Filename
				err = os.WriteFile(path, fileTransferMessage.Data, 0644)
				if err != nil {
					fmt.Println("Error saving file")	
					continue
				}
				fileInfo := file.NewFileInfo(fileTransferMessage.Filename, originalOwner, int64(len(fileTransferMessage.Data)), fileTransferMessage.Hash, fileTransferMessage.Signature)
				err = file.AddToFileList("files/file_list.json", fileInfo);
				if err != nil {
					fmt.Println("Error Adding file to file list")
					fmt.Println(err)
				}
			}
        default:
            log.Println("unknown message type:", baseMessage.Type)
        }
    }
}	