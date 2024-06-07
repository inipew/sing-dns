package dns

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/task"

	"github.com/miekg/dns"
)

type myUpstreamHandler interface {
	DialContext(ctx context.Context) (net.Conn, error)
	ReadMessage(conn net.Conn) (*dns.Msg, error)
	WriteMessage(conn net.Conn, message *dns.Msg) error
}

type myUpstreamAdapter struct {
	ctx        context.Context
	cancel     context.CancelFunc
	dialer     N.Dialer
	serverAddr M.Socksaddr
	reuse      bool
	handler    myUpstreamHandler
	access     sync.Mutex
	conn       *dnsConnection
}

func newUpstreamAdapter(options UpstreamOptions, serverAddr M.Socksaddr, reuse bool) myUpstreamAdapter {
	ctx, cancel := context.WithCancel(options.Context)
	return myUpstreamAdapter{
		ctx:        ctx,
		cancel:     cancel,
		dialer:     options.Dialer,
		serverAddr: serverAddr,
		reuse:      reuse,
	}
}

func (t *myUpstreamAdapter) Start() error {
	return nil
}

func (t *myUpstreamAdapter) open(ctx context.Context) (*dnsConnection, error) {
	var connection *dnsConnection
	if t.reuse {
		connection = t.conn
		if connection != nil {
			if !common.Done(connection.ctx) {
				return connection, nil
			}
		}
		t.access.Lock()
		defer t.access.Unlock()
		connection = t.conn
		if connection != nil {
			if !common.Done(connection.ctx) {
				return connection, nil
			}
		}
	}
	conn, err := t.handler.DialContext(ctx)
	if err != nil {
		return nil, err
	}
	connCtx, cancel := context.WithCancel(t.ctx)
	connection = &dnsConnection{
		Conn:      conn,
		ctx:       connCtx,
		cancel:    cancel,
		callbacks: make(map[uint16]*dnsCallback),
	}
	go t.recvLoop(connection)
	if t.reuse {
		t.conn = connection
	}
	return connection, nil
}

func (t *myUpstreamAdapter) recvLoop(conn *dnsConnection) {
	var group task.Group
	group.Append0(func(ctx context.Context) error {
		for {
			message, err := t.handler.ReadMessage(conn)
			if err != nil {
				return err
			}
			conn.access.RLock()
			callback, loaded := conn.callbacks[message.Id]
			conn.access.RUnlock()
			if !loaded {
				continue
			}
			callback.access.Lock()
			select {
			case <-callback.done:
			default:
				callback.message = message
				close(callback.done)
			}
			callback.access.Unlock()
		}
	})
	group.Cleanup(func() {
		conn.Close()
	})
	group.Run(conn.ctx)
}

func (t *myUpstreamAdapter) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	messageId := message.Id
	conn, err := t.open(t.ctx)
	if err != nil {
		return nil, err
	}
	response, err := t.exchange(ctx, conn, message)
	if err != nil {
		return nil, err
	}
	if !t.reuse {
		conn.Close()
	}
	response.Id = messageId
	return response, nil
}

func (t *myUpstreamAdapter) exchange(ctx context.Context, conn *dnsConnection, message *dns.Msg) (*dns.Msg, error) {
	messageId := message.Id
	callback := &dnsCallback{
		done: make(chan struct{}),
	}
	exMessage := *message
	conn.access.Lock()
	conn.queryId++
	exMessage.Id = conn.queryId
	conn.callbacks[exMessage.Id] = callback
	conn.access.Unlock()
	defer t.cleanup(conn, exMessage.Id, callback)
	var err error
	done := make(chan struct{})
	go func() {
		conn.writeAccess.Lock()
		err = t.handler.WriteMessage(conn, &exMessage)
		conn.writeAccess.Unlock()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		conn.Close()
		return nil, ctx.Err()
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	select {
	case <-callback.done:
		callback.message.Id = messageId
		return callback.message, nil
	case <-conn.ctx.Done():
		return nil, E.Errors(conn.err, conn.ctx.Err())
	case <-ctx.Done():
		conn.Close()
		return nil, ctx.Err()
	}
}

func (t *myUpstreamAdapter) cleanup(conn *dnsConnection, messageId uint16, callback *dnsCallback) {
	conn.access.Lock()
	delete(conn.callbacks, messageId)
	conn.access.Unlock()
	callback.access.Lock()
	select {
	case <-callback.done:
	default:
		close(callback.done)
	}
	callback.access.Unlock()
}

func (t *myUpstreamAdapter) Reset() {
	conn := t.conn
	if conn != nil {
		conn.Close()
	}
}

func (t *myUpstreamAdapter) Close() error {
	t.Reset()
	return nil
}

func (t *myUpstreamAdapter) Lookup(ctx context.Context, domain string, strategy DomainStrategy) ([]netip.Addr, error) {
	return nil, os.ErrInvalid
}

type dnsConnection struct {
	net.Conn
	ctx         context.Context
	cancel      context.CancelFunc
	access      sync.RWMutex
	writeAccess sync.Mutex
	err         error
	queryId     uint16
	callbacks   map[uint16]*dnsCallback
}

func (c *dnsConnection) Close() error {
	c.cancel()
	return c.Conn.Close()
}

type dnsCallback struct {
	access  sync.Mutex
	message *dns.Msg
	done    chan struct{}
}
