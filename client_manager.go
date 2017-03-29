package apns2

import (
	"container/list"
	"crypto/sha1"
	"crypto/tls"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"
)

import (
	"github.com/AlexStocks/apns2/certificate"
	Log "github.com/AlexStocks/log4go"
)

type managerItem struct {
	key      [sha1.Size]byte
	client   *Client
	lastUsed time.Time
}

type certEnv struct {
	cert       tls.Certificate
	useSandbox bool
}

// ClientManager is a way to manage multiple connections to the APNs.
type ClientManager struct {
	// MaxSize is the maximum number of clients allowed in the manager. When
	// this limit is reached, the least recently used client is evicted. Set
	// zero for no limit.
	MaxSize int

	// MaxAge is the maximum age of clients in the manager. Upon retrieval, if
	// a client has remained unused in the manager for this duration or longer,
	// it is evicted and nil is returned. Set zero to disable this
	// functionality.
	MaxAge time.Duration

	// Factory is the function which constructs clients if not found in the
	// manager.
	Factory func(certificate tls.Certificate) *Client

	// get tls.Certificate by certificate file
	certDict map[string]certEnv

	cache map[[sha1.Size]byte]*list.Element
	ll    *list.List
	mu    sync.Mutex
	once  sync.Once
}

// NewClientManager returns a new ClientManager for prolonged, concurrent usage
// of multiple APNs clients. ClientManager is flexible enough to work best for
// your use case. When a client is not found in the manager, Get will return
// the result of calling Factory, which can be a Client or nil.
//
// Having multiple clients per certificate in the manager is not allowed.
//
// By default, MaxSize is 64, MaxAge is 10 minutes, and Factory always returns
// a Client with default options.
func NewClientManager() *ClientManager {
	manager := &ClientManager{
		MaxSize: 64,
		MaxAge:  10 * time.Minute,
		Factory: NewClient,
	}

	manager.initInternals()

	return manager
}

// Add adds a Client to the manager. You can use this to individually configure
// Clients in the manager.
func (m *ClientManager) Add(client *Client) {
	m.initInternals()
	m.mu.Lock()
	defer m.mu.Unlock()

	key := cacheKey(client.Certificate)
	now := time.Now()
	if ele, hit := m.cache[key]; hit {
		item := ele.Value.(*managerItem)
		item.client = client
		item.lastUsed = now
		m.ll.MoveToFront(ele)
		return
	}
	ele := m.ll.PushFront(&managerItem{key, client, now})
	m.cache[key] = ele
	if m.MaxSize != 0 && m.ll.Len() > m.MaxSize {
		m.mu.Unlock()
		m.removeOldest()
		m.mu.Lock()
	}
}

// AddByCertFile adds a Client to the manager by certificate file @file. You can use this to individually configure
// Clients in the manager.
// @file : certificate file
// @pssword: @file's password
// @useSandbox: development or not(release)
func (m *ClientManager) AddByCertFile(file string, password string, useSandbox bool) error {
	var (
		err               error
		ext               string
		CertificatePemIos tls.Certificate
		client            *Client
	)

	ext = filepath.Ext(file)
	switch ext {
	case ".p12":
		CertificatePemIos, err = certificate.FromP12File(file, password)
	case ".pem":
		CertificatePemIos, err = certificate.FromPemFile(file, password)
	default:
		err = errors.New(fmt.Sprintf("wrong certificate key extension %s", ext))
	}

	if err != nil {
		Log.Error("key:%s, Cert Error:%v", file, err)

		return err
	}

	if useSandbox {
		client = NewClient(CertificatePemIos).Development()
	} else {
		client = NewClient(CertificatePemIos).Production()
	}
	m.Add(client)
	m.mu.Lock()
	m.certDict[file] = certEnv{CertificatePemIos, useSandbox}
	m.mu.Unlock()

	return nil
}

// Get gets a Client from the manager. If a Client is not found in the manager
// or if a Client has remained in the manager longer than MaxAge, Get will call
// the ClientManager's Factory function, store the result in the manager if
// non-nil, and return it.
func (m *ClientManager) Get(certificate tls.Certificate) *Client {
	m.initInternals()
	m.mu.Lock()
	defer m.mu.Unlock()

	key := cacheKey(certificate)
	now := time.Now()
	if ele, hit := m.cache[key]; hit {
		item := ele.Value.(*managerItem)
		if m.MaxAge != 0 && item.lastUsed.Before(now.Add(-m.MaxAge)) {
			item.client.reconnect()
			// c := m.Factory(certificate)
			// if c == nil {
			// 	return nil
			// }
			// item.client = c
		}
		item.lastUsed = now
		m.ll.MoveToFront(ele)
		return item.client
	}

	// !!! @c's Host is "https://api.development.push.apple.com"
	c := m.Factory(certificate)
	if c == nil {
		return nil
	}
	m.mu.Unlock()
	m.Add(c)
	m.mu.Lock()
	return c
}

func (m *ClientManager) GetByCertEnv(ce certEnv) *Client {
	m.initInternals()
	m.mu.Lock()
	defer m.mu.Unlock()

	key := cacheKey(ce.cert)
	now := time.Now()
	if ele, hit := m.cache[key]; hit {
		item := ele.Value.(*managerItem)
		if m.MaxAge != 0 && item.lastUsed.Before(now.Add(-m.MaxAge)) {
			item.client.reconnect()
			// c := m.Factory(certificate)
			// if c == nil {
			// 	return nil
			// }
			// item.client = c
		}
		item.lastUsed = now
		m.ll.MoveToFront(ele)
		return item.client
	}

	// !!! @c's Host is "https://api.development.push.apple.com"
	c := m.Factory(ce.cert)
	if c == nil {
		return nil
	}
	if ce.useSandbox {
		c = c.Development()
	} else {
		c = c.Production()
	}
	m.mu.Unlock()
	m.Add(c)
	m.mu.Lock()
	return c
}

// GetByCertFile gets a Client from the manager by its certificate file name. If @file's
// client does not exist, the return client is nil. If a Client is notfound in the manager
// or if a Client has remained in the manager longer than MaxAge, Get will call
// the ClientManager's Factory function, store the result in the manager if
// non-nil, and return it.
func (m *ClientManager) GetByCertFile(file string) *Client {
	var (
		ok bool
		ce certEnv
	)

	m.mu.Lock()
	ce, ok = m.certDict[file]
	m.mu.Unlock()
	if !ok {
		return nil
	}

	return m.GetByCertEnv(ce)
}

// Len returns the current size of the ClientManager.
func (m *ClientManager) Len() int {
	if m.cache == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ll.Len()
}

func (m *ClientManager) initInternals() {
	m.once.Do(func() {
		m.cache = map[[sha1.Size]byte]*list.Element{}
		m.certDict = map[string]certEnv{}
		m.ll = list.New()
	})
}

func (m *ClientManager) removeOldest() {
	m.mu.Lock()
	ele := m.ll.Back()
	m.mu.Unlock()
	if ele != nil {
		m.removeElement(ele)
	}
}

func (m *ClientManager) removeElement(e *list.Element) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ll.Remove(e)
	delete(m.cache, e.Value.(*managerItem).key)
}

func cacheKey(certificate tls.Certificate) [sha1.Size]byte {
	var data []byte

	for _, cert := range certificate.Certificate {
		data = append(data, cert...)
	}

	return sha1.Sum(data)
}
