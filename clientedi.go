package clientedi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
)

// Vars for logging
var (
	// Trace logging key
	Trace *log.Logger
	// Info logging key
	Info *log.Logger
	// Warning logging key
	Warning *log.Logger
	// Error logging key
	Error *log.Logger
)

// Init initializes the logging structures
func Init(
	traceHandle io.Writer,
	infoHandle io.Writer,
	warningHandle io.Writer,
	errorHandle io.Writer) {

	Trace = log.New(traceHandle,
		"TRACE: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Info = log.New(infoHandle,
		"INFO: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Warning = log.New(warningHandle,
		"WARNING: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Error = log.New(errorHandle,
		"ERROR: ",
		log.Ldate|log.Ltime|log.Lshortfile)
}

// Edistatus to pass unique errors back to callers
type Edistatus struct {
	Op      string
	Number  int
	Message string
	Len     int16
}

// Connect to HP3000 EDI Server.
func Connect(addr string) (*net.TCPConn, Edistatus) {
	Init(ioutil.Discard, os.Stdout, os.Stderr, os.Stderr)
	// Init(ioutil.Discard, os.Stdout, os.Stdout, os.Stderr)
	Info.Printf("Connect: %s\n", addr)
	var retval Edistatus
	retval.Len = 0
	strAck := "Y"
	strEcho := "123456789012345678901234567890123456789012345678901234567890"
	reply := make([]byte, 1024)
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		retval.Op = "ioedi.Connect ResolveTCPAddr"
		retval.Number = 1
		retval.Message = err.Error()
		Error.Printf("Connect ResolveTCPAddr Error=%d\n", retval.Number)
		Error.Printf("ResolveTCPAddr Error %s\n", retval.Message)
		return nil, retval
	}

	// Start connection to server.
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		retval.Op = "ioedi.Connect DailTCP"
		retval.Number = 2
		retval.Message = err.Error()
		Error.Printf("Connect DialTCP Error=%d\n", retval.Number)
		Error.Printf("DialTCP Error %s\n", retval.Message)
		return nil, retval
	}

	// Send security string to the server.
	_, err = conn.Write([]byte(strEcho))
	if err != nil {
		retval.Op = "ioedi.Connect Write security"
		retval.Number = 3
		retval.Message = err.Error()
		Error.Printf("Connect Security Write Error=%d\n", retval.Number)
		Error.Printf("Security Write Error %s\n", retval.Message)
		return nil, retval
	}
	// Receive initial PASS/FAIL from the server connect.
	reply = make([]byte, 1024)
	_, err = conn.Read(reply)
	if err != nil {
		retval.Op = "ioedi.Connect Read PASS/FAIL"
		retval.Number = 4
		retval.Message = err.Error()
		Error.Printf("Connect Security Read Error=%d\n", retval.Number)
		Error.Printf("Security Read Error %s\n", retval.Message)
		return nil, retval
	}
	_, err = conn.Write([]byte(strAck))
	if err != nil {
		retval.Op = "ioedi.Connect Write ACK"
		retval.Number = 5
		retval.Message = err.Error()
		Error.Printf("Connect Acknowlegement Write Error=%d\n", retval.Number)
		Error.Printf("Acknowlegement Write Error %s\n", retval.Message)
		return nil, retval
	}
	Info.Printf("Connect: %s was Successfull \n", addr)
	return conn, retval
}

// InLength Get Length of data to be received, before Recv
func inLength(c *net.TCPConn) (int16, Edistatus) {
	var retval Edistatus
	lenbuf := new(bytes.Buffer)
	netlen := int16(0)
	retval.Len = 0
	binary.Write(lenbuf, binary.BigEndian, uint16(netlen))
	_, err := c.Read(lenbuf.Bytes())
	if err != nil {
		retval.Op = "ioedi.inLength Read"
		retval.Number = 1
		retval.Message = err.Error()
		return 0, retval
	}
	binary.Read(lenbuf, binary.BigEndian, &netlen)
	retval.Len = netlen
	return netlen, retval
}
func sendAck(c *net.TCPConn) Edistatus {
	var retval Edistatus
	strAck := "Y"
	_, err := c.Write([]byte(strAck))
	if err != nil {
		retval.Op = "ioedi.sendAck Write"
		retval.Number = 1
		retval.Message = err.Error()
		return retval
	}
	return retval
}

// Recv Receive data from HP3000
func Recv(c *net.TCPConn) (string, Edistatus) {
	// Init(os.Stdout, os.Stdout, os.Stderr, os.Stderr)
	// Init(ioutil.Discard, os.Stdout, os.Stdout, os.Stderr)
	Trace.Printf("Recv From: %v \n", c.RemoteAddr())
	len, retval := inLength(c)
	if retval.Number != 0 {
		Error.Printf("Recv: inLength Error=%d\n", retval.Number)
		Error.Printf("inLength Error %s\n", retval.Message)
		return "", retval
	}
	Trace.Printf("Recv length: %d \n", len)
	if len < 0 {
		retval.Len = len
		retval.Op = "ioedi.Recv EOF"
		retval.Number = -9999
		retval.Message = "Received negative lenght (EOF)"
		return "", retval
	}
	Trace.Printf("ioedi.Recv len=%d\n", len)
	reply := make([]byte, 4096)
	buffer := new(bytes.Buffer)
	buffer.Grow(int(len))
	bytecnt := 0
	for bytecnt = 0; bytecnt < int(len); {
		reply = make([]byte, 4096)
		len, err := c.Read(reply)
		if err != nil {
			retval.Op = "ioedi.Recv Read"
			retval.Number = 1
			retval.Message = err.Error()
			Error.Printf("Recv: Read Error=%d\n", retval.Number)
			Error.Printf("Read Error %s\n", retval.Message)
			return "", retval
		}
		bytecnt = bytecnt + len
		// Append bytes received to buffer
		buffer.WriteString(string(reply))
	}
	retval = sendAck(c)
	if retval.Number != 0 {
		retval.Len = 0
		return "", retval
	}
	Trace.Printf("Recv: Received Length=%d\n", bytecnt)
	Trace.Printf("Recv: Received Data [%s]\n", buffer.String())
	retval.Len = int16(bytecnt)
	newstr := buffer.String()
	return newstr, retval
}

func recvAck(c *net.TCPConn) Edistatus {
	var retval Edistatus
	retval.Op = "ioedi.recvAck Read"
	reply := make([]byte, 1)
	_, err := c.Read(reply)
	if err != nil {
		retval.Number = 1
		retval.Message = err.Error()
		return retval
	}
	if string(reply) == "Y" {
		retval.Number = 0
		retval.Message = "Successfully received ACK"
		return retval
	}
	retval.Number = 2
	retval.Message = "Failed to receive ACK, maybe out of sync"
	return retval
}

func sendLength(c *net.TCPConn, str string) (int16, Edistatus) {
	var retval Edistatus
	retval.Len = 0
	lenbuf := new(bytes.Buffer)
	netlen := int16(len(str))
	binary.Write(lenbuf, binary.BigEndian, uint16(netlen))
	_, err := c.Write(lenbuf.Bytes())
	if err != nil {
		retval.Op = "ioedi.sendLength Write"
		retval.Number = 1
		retval.Message = err.Error()
		return netlen, retval
	}
	retval.Len = netlen
	return netlen, retval
}

func sendData(c *net.TCPConn, str string) (int16, Edistatus) {
	var retval Edistatus
	cnt, err := c.Write([]byte(str))
	if err != nil {
		retval.Op = "ioedi.sendData Write"
		retval.Number = 1
		retval.Message = err.Error()
		return int16(cnt), retval
	}
	return int16(cnt), retval
}

// Send data to the HP3000.
func Send(c *net.TCPConn, str string) Edistatus {
	readyCount, retval := sendLength(c, str)
	Trace.Printf("Send: Sending Length=%d\n", readyCount)
	Trace.Printf("Send: Sending Data [%s]\n", str)
	if retval.Number != 0 {
		return retval
	}

	sentCount, retval := sendData(c, str)
	if retval.Number != 0 {
		return retval
	}
	if readyCount < sentCount {
		retval.Op = "ioedi.Send Failure"
		retval.Number = 1
		retval.Message = fmt.Sprintf("Send failed to send all data, expected %d but sent %d\n", readyCount, sentCount)
		return retval
	}
	Trace.Printf("Send: Successfully Sent Length=%d\n", sentCount)
	return recvAck(c)
}

// Disconnect HP3000 socket
func Disconnect(c *net.TCPConn) Edistatus {
	Info.Printf("Disconnect from : %s\n", c.RemoteAddr())
	var retval Edistatus
	lenbuf := new(bytes.Buffer)
	netlen := int16(-9999)
	retval.Len = netlen
	binary.Write(lenbuf, binary.BigEndian, uint16(netlen))
	_, err := c.Write(lenbuf.Bytes())
	if err != nil {
		retval.Op = "ioedi.Disconnect Write"
		retval.Number = 1
		retval.Message = err.Error()
		return retval
	}

	Recv(c)
	sendAck(c)
	c.Close()
	Info.Printf("Disconnect from : %s Clean, and Successfull \n", c.RemoteAddr())
	return retval
}
