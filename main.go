package main

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	sdk "github.com/cosmos/cosmos-sdk/types"

	// "github.com/davecgh/go-spew/spew"
	"github.com/blockchain-tps-test/samples/cosmos/tps"
	"github.com/pkg/errors"
)

var (
	Endpoint = []string{
		"tcp://10.10.1.1:26657",
	}
	mutex    sync.Mutex
	PrivKey  = "656575bd1f7f9710f2f0780de101294f4524e5f9eac4a6d23b7c64ada4e74f24"
	PrivKey2 = "e4b87f532e3c009ca45089811b6302c2b39ea9be97d5b718748671cd9f268777"
	PrivKey3 = "098cc9ba1d5109b4b81fc06859dc99950617e9d50127ca940e8298bd9fb3c6eb"
	// PrivKey4 = "098cc9ba1d5109b4b81fc06859dc99950617e9d50127ca940e8298bd9fb3c6eb"

	Timeout         = 15 * time.Second
	MaxConcurrency  = runtime.NumCPU() - 2
	txMap           map[string]time.Time
	txMapCrossChain map[string]time.Time
	model           = "cosmos_crosschain" //cosmos_crosschain cosmos_nocrosschain
)

func createRandomAccounts(accNum int) []sdk.AccAddress {
	testAddrs := make([]sdk.AccAddress, accNum)
	for i := 0; i < accNum; i++ {
		pk := ed25519.GenPrivKey().PubKey()
		testAddrs[i] = sdk.AccAddress(pk.Address())
	}

	return testAddrs
}

func main() {
	txMap = make(map[string]time.Time)
	txMapCrossChain = make(map[string]time.Time)
	var (
		mesuringDuration = 600 * time.Second
		queueSize        = 100
		concurrency      = 1
		queue            = tps.NewQueue(queueSize)
		closing          uint32
		idlingDuration   uint32
		logLevel         = tps.WARN_LEVEL // INFO_LEVEL, WARN_LEVEL, FATAL_LEVEL
		logger           = tps.NewLogger(logLevel)
		privs            = []string{
			PrivKey,
			//PrivKey2,
			//PrivKey3,
			/// PrivKey4,
		}

		testAddrs = createRandomAccounts(100)
	)

	go func() {
		defer atomic.AddUint32(&closing, 1)
		time.Sleep(mesuringDuration)
		fmt.Println("over------------------------")
	}()
	var client_list []CosmosClient
	// client, err := NewClient(Endpoint[0])
	// if err != nil {
	// 	logger.Fatal("err NewClient: ", err)
	// }
	for i := 0; i < concurrency; i++ {

		client, err := NewClient(Endpoint[i])

		if err != nil {
			logger.Fatal("err NewClient: ", err)
		}
		client_list = append(client_list, client)
	}
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()

	addrs := make([]string, len(privs))
	for i := range privs {
		addr, err := AccAddressFromPrivString(privs[i])
		if err != nil {
			logger.Fatal("err AccAddressFromPrivString: ", err)
		}
		addrs[i] = addr

		acc, err := client_list[0].Account(ctx, addr)
		if err != nil {
			logger.Fatal("err Account: ", err)
		}

		accNums[addr] = acc.GetAccountNumber()
	}

	wallet, err := tps.NewWallet(ctx, &client_list[0], privs, addrs)
	if err != nil {
		logger.Fatal("err NewWallet: ", err)
	}

	taskDo := func(t tps.Task, id int) error {
		task, ok := t.(*CosmTask)
		if !ok {
			return errors.New("unexpected task type")
		}

		ctx, cancel := context.WithTimeout(context.Background(), Timeout)
		defer cancel()

		var (
			priv         = wallet.Priv(id)
			currentNonce = wallet.IncrementNonce(priv)
		)
		if err = task.Do(ctx, &client_list[id], priv, currentNonce, &queue, logger); err != nil {
			if errors.Is(err, tps.ErrWrongNonce) {
				wallet.RecetNonce(priv, currentNonce)
				task.tryCount = 0
				queue.Push(task)
				return nil
			}
			return errors.Wrap(err, "err Do")
		}

		// time.Sleep(ToDuration(&idlingDuration))

		return nil
	}

	worker := tps.NewWorker(taskDo)

	// performance likely not improved, whene exceed available cpu core
	if concurrency > MaxConcurrency {
		logger.Warn(fmt.Sprintf("concurrency setting is over logical max(%d)", MaxConcurrency))
	}
	for i := 0; i < concurrency; i++ {
		go worker.Run(&queue, i)
	}

	go func() {
		count := 0
		for {
			if atomic.LoadUint32(&closing) == 1 {
				break
			}

			if queue.CountTasks() > queueSize {
				continue
			}

			queue.Push(&CosmTask{
				to:     testAddrs[count%len(testAddrs)],
				amount: 1,
			})
			count++
		}
	}()
	client1, _ := NewClient("tcp://10.10.1.5:26657")
	if err = tps.StartTPSMeasuring(context.Background(), client1, &closing, &idlingDuration, logger); err != nil {
		logger.Fatal("err StartTPSMeasuring: ", err)
	}
}
