package transport

import (
	"GoClient/auth"
	"GoClient/consent"
	"GoClient/crypto"
	"GoClient/discovery"
	file "GoClient/file_manager"
	"GoClient/protocol"
	"GoClient/session"
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

func ConnectToPeer(peer *discovery.Peer, selfName, password string) (*session.SecureSession, error) {
	addr := net.JoinHostPort(peer.IP, fmt.Sprintf("%d", peer.Port))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	framed := session.NewFramedConn(conn)
	peerPubKeys, err := discovery.LoadPeerKeys("keys/peer_pub_keys.json"); if err != nil {
		return nil, err
	}

	peerPubKey := peerPubKeys[peer.Name]
	var secureSession *session.SecureSession
	if peerPubKey == nil {
		secureSession, err = auth.RunClientSideDhEKE(framed, password, selfName, peer.Name); if err != nil {
			return nil, err
		}
	} else {
		fmt.Print("\n\n\nRUNNING STS!!!!!!!!!!!!!\n\n\n")
		secureSession, err = auth.RunClientSideSTS(framed, selfName, peer.Name); if err != nil {
			return nil, err
		}
	}

	fmt.Printf("Success connecting to: %s\n", peer.Name)
	return secureSession, nil
}

func RunSecureClientSession(session *session.SecureSession) {
	scanner := bufio.NewScanner(os.Stdin)
    fmt.Println("Enter 'files' to view peer files, get <filename> to request a file:")
	defer session.Close()

    for {

		select {
		case req := <-consent.Ch:
			fmt.Println("consent request:", req.Message)
			fmt.Print("accept? (y/n): ")
			scanner.Scan()
			res := scanner.Text()
			req.Response <- res == "y"
			if res == "y" {
				fmt.Println("\nFile Accepted, waiting for transfer")
			} else {
				fmt.Println("\nFile Declined")
			}
			continue
		default:
		}

        fmt.Print("> ")
        if !scanner.Scan() {
            break
        }
		parts := strings.Fields(scanner.Text())

        switch parts[0] {
        case "":
            continue
        case "files":
			fileListRequestMessage, err := protocol.BuildFileListRequest(session.SelfName); if err != nil {
				fmt.Println("Error, could not build fileListRequest")
				continue
			}

			err = session.Send(fileListRequestMessage); if err != nil {
				fmt.Println("Error, could not send fileListRequest")
				fmt.Printf("ERR: %s", err)
				continue
			}

			fileListRaw, err := session.Recv(); if err != nil {
				fmt.Println("Error, could not recv fileList")
				continue
			}

			fileListMessage, err := protocol.ParseMessage[protocol.FileListResponseMessage](fileListRaw); if err != nil {
				fmt.Println("Error parsing fileList response")
				continue
			}

			fmt.Printf("%s's File List:\n\n", session.PeerName)
			for _, file := range fileListMessage.Files {
				fmt.Printf("- %s, {%s}\n", file.Name, file.OriginalOwner)
			}
		case "get":

			if len(parts) < 2 {
        	    fmt.Println("usage: get <filename>")
            	continue
        	}
			filename := parts[1]
			fileRequest, _ := protocol.BuildFileRequest(session.SelfName, filename)
			session.Send(fileRequest)
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

				err = crypto.RsaPssVerify(correspondingPubKey, fileTransferMessage.Data, string(fileTransferMessage.Signature)); if err != nil {
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
		case "send":
			if len(parts) < 2 {
        	    fmt.Println("usage: send <filename>")
            	continue
        	}

			filename := parts[1]
			myFileList, err := file.LoadFileList("files/file_list.json"); if err != nil {
				fmt.Println("could not load file list")
			}

			var fileInfo *file.FileInfo
			for _, file := range myFileList {
				if file.Name == filename {
					fileInfo = file
				}
			}

			if fileInfo == nil {
				fmt.Println("Specified file not found in file_list.json")
				continue
			}

			path := "files/" + filename
			file, err := os.ReadFile(path); if err != nil {
				fmt.Println("File could not be read")
				continue
			}

			consentRequest, _ := protocol.BuildConsentRequest(session.SelfName, filename, int64(len(file)))
			session.Send(consentRequest)

			resRaw, err := session.Recv(); if err != nil {
				fmt.Println("Error, could not recv response")
				continue
			}

			consentResponse, err := protocol.ParseMessage[protocol.ConsentResponseMessage](resRaw);
			if err != nil {
				fmt.Println("Could not parse consent response")
				continue
			}

			if !consentResponse.Accepted {
				fmt.Println("Peer declined request")
				continue
			}

			fileTransferMessage, err := protocol.BuildFileTransfer(session.SelfName, fileInfo.Name, fileInfo.OriginalOwner, fileInfo.Hash, fileInfo.Signature, file); if err != nil {
				errMsg, _ := protocol.BuildErrorMessage(session.SelfName, "Could not build fileTransfer message")
				session.Send(errMsg)
				continue
			}
			session.Send(fileTransferMessage)
        case "quit":
			return
        }
    }
}