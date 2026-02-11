package nwep

/*
#include <nwep/nwep.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import "unsafe"

const (
	PoolMaxServers          = C.NWEP_POOL_MAX_SERVERS
	PoolHealthCheckFailures = C.NWEP_POOL_HEALTH_CHECK_FAILURES
)

type PoolStrategy int

const (
	PoolRoundRobin PoolStrategy = C.NWEP_POOL_ROUND_ROBIN
	PoolRandom     PoolStrategy = C.NWEP_POOL_RANDOM
)

type ServerHealth int

const (
	ServerHealthy   ServerHealth = C.NWEP_SERVER_HEALTHY
	ServerUnhealthy ServerHealth = C.NWEP_SERVER_UNHEALTHY
)

type PoolServer struct {
	URL                 string
	Health              ServerHealth
	ConsecutiveFailures int
	LastSuccess         Tstamp
	LastFailure         Tstamp
}

func PoolSettingsDefault() *PoolSettings {
	var cs C.nwep_log_server_pool_settings
	C.nwep_log_server_pool_settings_default(&cs)
	return &PoolSettings{
		Strategy:    PoolStrategy(cs.strategy),
		MaxFailures: int(cs.max_failures),
	}
}

type PoolSettings struct {
	Strategy    PoolStrategy
	MaxFailures int
}

type LogServerPool struct {
	c *C.nwep_log_server_pool
}

func NewLogServerPool(settings *PoolSettings) (*LogServerPool, error) {
	pool := &LogServerPool{}
	var cs *C.nwep_log_server_pool_settings
	var csettings C.nwep_log_server_pool_settings
	if settings != nil {
		csettings.strategy = C.nwep_pool_strategy(settings.Strategy)
		csettings.max_failures = C.int(settings.MaxFailures)
		cs = &csettings
	}
	rv := C.nwep_log_server_pool_new(&pool.c, cs)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return pool, nil
}

func (p *LogServerPool) Free() {
	if p.c != nil {
		C.nwep_log_server_pool_free(p.c)
		p.c = nil
	}
}

func (p *LogServerPool) Add(url string) error {
	curl := C.CString(url)
	defer C.free(unsafe.Pointer(curl))
	return errorFromCode(int(C.nwep_log_server_pool_add(p.c, curl)))
}

func (p *LogServerPool) Remove(url string) error {
	curl := C.CString(url)
	defer C.free(unsafe.Pointer(curl))
	return errorFromCode(int(C.nwep_log_server_pool_remove(p.c, curl)))
}

// Select picks a healthy server from the pool using the configured strategy.
func (p *LogServerPool) Select() (*PoolServer, error) {
	var cps C.nwep_pool_server
	rv := C.nwep_log_server_pool_select(p.c, &cps)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return poolServerFromC(&cps), nil
}

func (p *LogServerPool) MarkSuccess(url string, now Tstamp) {
	curl := C.CString(url)
	defer C.free(unsafe.Pointer(curl))
	C.nwep_log_server_pool_mark_success(p.c, curl, C.nwep_tstamp(now))
}

func (p *LogServerPool) MarkFailure(url string, now Tstamp) {
	curl := C.CString(url)
	defer C.free(unsafe.Pointer(curl))
	C.nwep_log_server_pool_mark_failure(p.c, curl, C.nwep_tstamp(now))
}

func (p *LogServerPool) Size() int {
	return int(C.nwep_log_server_pool_size(p.c))
}

func (p *LogServerPool) HealthyCount() int {
	return int(C.nwep_log_server_pool_healthy_count(p.c))
}

func (p *LogServerPool) Get(index int) (*PoolServer, error) {
	var cps C.nwep_pool_server
	rv := C.nwep_log_server_pool_get(p.c, C.size_t(index), &cps)
	if err := errorFromCode(int(rv)); err != nil {
		return nil, err
	}
	return poolServerFromC(&cps), nil
}

// ResetHealth marks all servers in the pool as healthy.
func (p *LogServerPool) ResetHealth() {
	C.nwep_log_server_pool_reset_health(p.c)
}

func poolServerFromC(cps *C.nwep_pool_server) *PoolServer {
	return &PoolServer{
		URL:                 C.GoString(&cps.url[0]),
		Health:              ServerHealth(cps.health),
		ConsecutiveFailures: int(cps.consecutive_failures),
		LastSuccess:         Tstamp(cps.last_success),
		LastFailure:         Tstamp(cps.last_failure),
	}
}
