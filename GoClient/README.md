# Go Client

### How to run

## Installation

```bash
git clone https://github.com/JacobMcM/CISC468-P2P-Secure-File-Sharing-App
cd CISC468-P2P-Secure-File-Sharing-App/GoClient
```

## Running

```bash
go run main.go
```

## Usage

Once running, you will see a prompt:

```
Enter a peer name to connect, or 'peers' to list:
>
```

### List available peers

```
> peers
  - Liam-PC @ 123.456.7.89:5011
  - JacobPC @ 123.456.7.98:5000
```

### Connect to a peer

```
> JacobPC
Connecting to JacobPC...
Enter shared password: ********
...
Connected to JacobPC
```

## Testing

```bash
go run main.go
> peers
  - Liam-PC @ 123.456.7.89:5011
> Liam-PC
...
Connected to Liam-PC
> files
Liam-PC's File List:
- bee_movie.txt, {Liam-PC}
- hello.txt, {Liam-PC}
> get bee_movie.txt
Received file: bee_movie.txt
Original owner: Liam-PC
Verifying signature using Liam-PC's public key
VERIFICATION SUCCESS
```
