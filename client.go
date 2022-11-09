package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"regexp"
	"time"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/simapp"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	xauthsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	txtypes "github.com/cosmos/cosmos-sdk/x/auth/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	transfertypes "github.com/cosmos/ibc-go/v4/modules/apps/transfer/types"
	clienttypes "github.com/cosmos/ibc-go/v4/modules/core/02-client/types"

	// "github.com/davecgh/go-spew/spew"
	"github.com/blockchain-tps-test/samples/cosmos/tps"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	rpchttp "github.com/tendermint/tendermint/rpc/client/http"
	ctypes "github.com/tendermint/tendermint/rpc/core/types"
	"google.golang.org/grpc"
)

const (
	DefalultRPCURI = "tcp://127.0.0.1:26657"
)

var (
	_ tps.Client = (*CosmosClient)(nil)

	ChainID              = "earth"
	Denom                = "coin"
	AccountAddressPrefix = "earth"

	accNums = make(map[string]uint64)
)

type CosmosClient struct {
	conn *grpc.ClientConn

	clientHTTP *rpchttp.HTTP
	authClient authtypes.QueryClient

	cdc      *codec.ProtoCodec
	txConfig client.TxConfig
}

func init() {
	config := sdk.GetConfig()
	config.SetBech32PrefixForAccount(AccountAddressPrefix, AccountAddressPrefix+sdk.PrefixPublic)
	config.Seal()
}

func NewClient(rpcURI string) (CosmosClient, error) {
	var (
		c      = CosmosClient{}
		encCfg = simapp.MakeTestEncodingConfig()
		err    error
	)

	if rpcURI == "" {
		rpcURI = DefalultRPCURI
	}

	if c.clientHTTP, err = rpchttp.New(rpcURI, "/websocket"); err != nil {
		return c, err
	}

	if c.conn, err = grpc.Dial("127.0.0.1:9090", grpc.WithInsecure()); err != nil {
		return c, err
	}

	c.authClient = authtypes.NewQueryClient(c.conn)

	c.cdc = codec.NewProtoCodec(encCfg.InterfaceRegistry)
	c.txConfig = txtypes.NewTxConfig(c.cdc, txtypes.DefaultSignModes)

	return c, nil
}

func (c CosmosClient) LatestBlockHeight(ctx context.Context) (uint64, error) {
	res, err := c.clientHTTP.Block(ctx, nil)
	if err != nil {
		return 0, err
	}
	return uint64(res.Block.Header.Height), nil
}

func (c CosmosClient) CountTx(ctx context.Context, height uint64) (int, time.Duration, error) {
	h := int64(height)
	res, err := c.clientHTTP.Block(ctx, &h)
	//res.Block.Data.Txs[0]
	if err != nil {
		return 0, 0, err
	}
	var elapsedTime time.Duration
	elapsedTime = 0
	result := 0
	if model == "cosmos_nocrosschain" {
		for _, tx := range res.Block.Data.Txs {
			mutex.Lock()
			startTime := txMap[string(tx.Hash())]
			mutex.Unlock()
			elapsedTime = elapsedTime + time.Since(startTime)
			result += 1
		}
		if result != 0 {
			fmt.Println("latency is", elapsedTime/time.Duration(result))
		}
	} else {

		for _, tx := range res.Block.Data.Txs {
			//fmt.Println(tx)
			time.Sleep(200 * time.Millisecond)
			resultTx, _ := c.clientHTTP.Tx(ctx, tx.Hash(), false)
			//time.Sleep(200 * time.Millisecond)
			if resultTx == nil {
				continue
			}
			fmt.Println(resultTx.TxResult.Log)
			matchStr := regexp.MustCompile("\"key\":\"packet_sequence\",\"value\":\"(.*?)\"").FindStringSubmatch(resultTx.TxResult.Log)
			if len(matchStr) > 0 {
				fmt.Println("YES", matchStr[len(matchStr)-1])
				mutex.Lock()
				startTime, ok := txMapCrossChain[matchStr[len(matchStr)-1]]
				mutex.Unlock()
				fmt.Println(time.Since(startTime))
				elapsedTime = elapsedTime + time.Since(startTime)
				if ok {
					fmt.Println("!", time.Since(startTime))
				}

				result += 1
			}
		}
		if result != 0 {
			fmt.Println("latency is", elapsedTime/time.Duration(result))
		}

	}
	//res.Block.Data.Txs[0].Hash()
	if result != 0 {
		return len(res.Block.Data.Txs), elapsedTime / time.Duration(result), nil
	} else {
		return len(res.Block.Data.Txs), 0, nil
	}

}

func (c CosmosClient) CountPendingTx(ctx context.Context) (int, error) {
	res, err := c.clientHTTP.UnconfirmedTxs(ctx, nil)
	if err != nil {
		return 0, err
	}
	return int(res.Total), nil
}

func (c CosmosClient) Nonce(ctx context.Context, address string) (uint64, error) {
	acc, err := c.Account(ctx, address)
	if err != nil {
		return 0, err
	}
	return acc.GetSequence(), nil
}

func (c CosmosClient) Account(ctx context.Context, address string) (acc authtypes.AccountI, err error) {
	req := &authtypes.QueryAccountRequest{Address: address}
	res, err := c.authClient.Account(ctx, req)
	if err != nil {
		return
	}

	if err = c.cdc.UnpackAny(res.GetAccount(), &acc); err != nil {
		return
	}

	return
}

func (c CosmosClient) Close() {
	c.conn.Close()
}

func PrivFromString(privStr string) (priv cryptotypes.PrivKey, err error) {
	priBytes, err := hex.DecodeString(privStr)
	if err != nil {
		return
	}
	priv = &secp256k1.PrivKey{Key: priBytes}
	return
}

func AccAddressFromPriv(priv cryptotypes.PrivKey) sdk.AccAddress {
	return sdk.AccAddress(priv.PubKey().Address().Bytes())
}

func AccAddressFromPrivString(privStr string) (string, error) {
	priv, err := PrivFromString(privStr)
	if err != nil {
		return "", err
	}
	return AccAddressFromPriv(priv).String(), nil
}

func (c *CosmosClient) BuildTx(msg sdk.Msg, priv cryptotypes.PrivKey, accSeq uint64) (authsigning.Tx, error) {
	var (
		txBuilder = c.txConfig.NewTxBuilder()
		accNum    = accNums[AccAddressFromPriv(priv).String()]
	)

	err := txBuilder.SetMsgs(msg)
	if err != nil {
		return nil, err
	}
	txBuilder.SetGasLimit(uint64(flags.DefaultGasLimit))

	// First round: we gather all the signer infos. We use the "set empty signature" hack to do that.
	if err = txBuilder.SetSignatures(signing.SignatureV2{
		PubKey: priv.PubKey(),
		Data: &signing.SingleSignatureData{
			SignMode:  c.txConfig.SignModeHandler().DefaultMode(),
			Signature: nil,
		},
		Sequence: accSeq,
	}); err != nil {
		return nil, err
	}

	// Second round: all signer infos are set, so each signer can sign.
	signerData := xauthsigning.SignerData{
		ChainID:       ChainID,
		AccountNumber: accNum,
		Sequence:      accSeq,
	}
	sigV2, err := tx.SignWithPrivKey(
		c.txConfig.SignModeHandler().DefaultMode(), signerData,
		txBuilder, priv, c.txConfig, accSeq)
	if err != nil {
		return nil, err
	}
	if err = txBuilder.SetSignatures(sigV2); err != nil {
		return nil, err
	}

	return txBuilder.GetTx(), nil
}

type intoAny interface {
	AsAny() *codectypes.Any
}

var coun int = 0

func (c *CosmosClient) SendTx(ctx context.Context, privStr string, seq uint64, to sdk.AccAddress, amount int64) (*ctypes.ResultBroadcastTx, error) {
	priv, err := PrivFromString(privStr)
	if err != nil {
		return nil, err
	}
	var (
		timeoutHeight    uint64
		timeoutTimestamp uint64
	)
	clientHeight, _ := c.LatestBlockHeight(ctx)
	timeoutHeight = clientHeight + 1000
	timeoutTimestamp = 0
	token, err := sdk.ParseCoinNormalized("1coin")
	time.Sleep(1000 * time.Millisecond)
	if model == "cosmos_nocrosschain" {
		var (
			from  = AccAddressFromPriv(priv)
			coins = sdk.NewCoins(sdk.NewInt64Coin(Denom, amount))
			msg   = banktypes.NewMsgSend(from, to, coins)
		)
		//fmt.Println(msg1)
		tx, err := c.BuildTx(msg, priv, seq-1)
		if err != nil {
			return nil, err
		}

		txBytes, err := c.txConfig.TxEncoder()(tx)
		if err != nil {
			return nil, err
		}

		//res, err := c.clientHTTP.BroadcastTxSync(ctx, txBytes)
		res, err := c.clientHTTP.BroadcastTxAsync(ctx, txBytes)
		startTime := time.Now()
		mutex.Lock()
		txMap[string(res.Hash)] = startTime
		mutex.Unlock()

		// txb, err := c.txConfig.TxDecoder()(resultTx.Tx)
		// if err != nil {
		// 	return nil, err
		// }
		// p, ok := txb.(intoAny)
		// if !ok {
		// 	return nil, fmt.Errorf("expecting a type implementing intoAny, got: %T", txb)
		// }
		// any := p.AsAny()
		// resp:=sdk.NewResponseResultTx(resultTx, any, time.Now().Format(time.RFC3339))
		// fmt.Println(resp.Events)
		// Note: In async case, response is returnd before TxCheck
		// res, err := c.clientHTTP.BroadcastTxAsync(ctx, txBytes)
		if errRes := client.CheckTendermintError(err, txBytes); errRes != nil {
			return nil, err
		}
		if res.Code != 0 {
			return nil, fmt.Errorf("code: %d, log: %s, codespace: %s\n", res.Code, res.Log, res.Codespace)
		}
		return res, nil
	} else {
		var (
			//from  = AccAddressFromPriv(priv)
			//coins = sdk.NewCoins(sdk.NewInt64Coin(Denom, amount))
			//msg   = banktypes.NewMsgSend(from, to, coins)
			msg1 = transfertypes.NewMsgTransfer("transfer", "channel-0", token, "earth1v7vay6uyg3n47ypzegtdd8v2kv7glvqtym4dr7", "mars1vd39966gj72wzsvvltcspzvdu7a545gkgfrvem", clienttypes.Height{
				RevisionNumber: clientHeight,
				RevisionHeight: timeoutHeight,
			}, timeoutTimestamp)
		)
		fmt.Println(seq)
		tx, err := c.BuildTx(msg1, priv, seq-1)
		if err != nil {
			return nil, err
		}

		txBytes, err := c.txConfig.TxEncoder()(tx)
		if err != nil {
			return nil, err
		}
		// if coun == 4 {
		// 	return nil, nil
		// }
		res, err := c.clientHTTP.BroadcastTxSync(ctx, txBytes)
		//res, err := c.clientHTTP.BroadcastTxAsync(ctx, txBytes)
		//fmt.Println(res)
		//fmt.Println(res.Code)
		time.Sleep(3 * time.Second)
		resultTx, _ := c.clientHTTP.Tx(ctx, res.Hash, false)
		if resultTx != nil {
			fmt.Println(resultTx.TxResult.Log)

			if resultTx != nil && resultTx.TxResult.Log != "" {
				matchStr := regexp.MustCompile("\"key\":\"packet_sequence\",\"value\":\"(.*?)\"").FindStringSubmatch(resultTx.TxResult.Log)
				if len(matchStr) != 0 {
					//fmt.Println(matchStr[len(matchStr)-1])
					startTime := time.Now()
					mutex.Lock()
					txMapCrossChain[matchStr[len(matchStr)-1]] = startTime
					fmt.Println("have ", matchStr[len(matchStr)-1])
					mutex.Unlock()
				}
			}
		}

		// txb, err := c.txConfig.TxDecoder()(resultTx.Tx)
		// if err != nil {
		// 	return nil, err
		// }
		// p, ok := txb.(intoAny)
		// if !ok {
		// 	return nil, fmt.Errorf("expecting a type implementing intoAny, got: %T", txb)
		// }
		// any := p.AsAny()
		// resp:=sdk.NewResponseResultTx(resultTx, any, time.Now().Format(time.RFC3339))
		// fmt.Println(resp.Events)
		// Note: In async case, response is returnd before TxCheck
		// res, err := c.clientHTTP.BroadcastTxAsync(ctx, txBytes)
		if errRes := client.CheckTendermintError(err, txBytes); errRes != nil {
			return nil, err
		}
		if res.Code != 0 {
			return nil, fmt.Errorf("code: %d, log: %s, codespace: %s\n", res.Code, res.Log, res.Codespace)
		}
		//coun += 1

		return res, nil
	}

}
