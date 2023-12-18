import streamlit as st
import streamlit.components.v1 as components
from web3 import Web3
from Crypto.Hash import keccak
import ecdsa
import codecs
import random
import binascii
import requests
import time
import base64
import json
import time
from mospy.clients import HTTPClient
import httpx
from mospy import Account, Transaction
#from eth_utils.curried import keccak
#from eth_abi import (encode_abi,decode_single)
#from hexbytes import HexBytes
#from web3._utils.encoding import to_hex

def to_base64(memo):
    memo_bytes = memo.encode('utf-8')
    # 使用base64编码
    encoded_memo = base64.b64encode(memo_bytes)
    # 将字节转换回字符串
    encoded_memo_str = encoded_memo.decode('utf-8')
    return encoded_memo_str
def wait(wait_time):
    st.write("等待处理", wait_time, "秒")
    my_bar = st.progress(0)
    for i in range(wait_time):
        time.sleep(1)
        press = (i + 1) * (100 / wait_time)
        press = int(press)
        if press >= 99.1:
            press = 100
        my_bar.progress(press)

def from_key(private_key):
    private_key_bytes = codecs.decode(private_key, 'hex')
    key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    public_key = "04" + binascii.hexlify(key_bytes).decode("utf-8")
    keccak_hash = keccak.new(digest_bits=256)
    public_key = public_key[2:]
    public_key = bytes.fromhex(public_key)
    keccak_hash.update(public_key)
    rawadd = keccak_hash.hexdigest()
    address = '0x' + rawadd[-40:]
    return address
def get_chainid(url):
    data={"jsonrpc":"2.0","method":"eth_chainId","params": [],"id":1}
    r=requests.post(url,json=data)
    rjson=r.json()
    chainid = int(rjson["result"], 16)
    return chainid

st.title("evm铭文 & COSMOS")

models = st.radio("",("手动","自动连打"))
text='data:,{"p":"bnbs-20","op":"mint","tick":"bnbn","amt":"1000"}'
#address = st.text_input(f"address")
text_data = ""
hex_text=""

if models == "手动":
    body = """
           <!DOCTYPE html>
    <html lang="en">
    <body>
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"
        integrity="sha384-DfXdz2htPH0lsSSs5nCTpuj/zy4C+OGpamoFVy38MVBnE+IbbVYUew+OrCXaRkfj"
        crossorigin="anonymous"></script>
    <button class="enableEthereumButton btn">Connect wallet</button>
    <button class="sendEthButton btn">start</button>
    </body>
    <script>
    const ethereumButton = document.querySelector('.enableEthereumButton');
    const sendEthButton = document.querySelector('.sendEthButton');
    let accounts = [];
    //Sending Ethereum to an address
    sendEthButton.addEventListener('click', () => {
      window.parent.ethereum
        .request({
          method: 'eth_sendTransaction',
          params: [
            {
              from: accounts[0],
              to: accounts[0],
              value: '0',
              data: '%s',
            },
          ],
        })
        .then((txHash) => console.log(txHash))
        .catch((error) => console.error);
    });
    
    ethereumButton.addEventListener('click', () => {
      getAccount();
    });
    
    async function getAccount() {
      accounts = await window.parent.ethereum.request({ method: 'eth_requestAccounts' });
    }
      </script>
    </html>
            """
    text_data = st.text_input(f"data示例:{text}")

    if text_data != "":
        utf8_text = str(text_data).encode('utf-8')  # 将文本转换为UTF-8编码的字节字符串
        hex_text = '0x' + codecs.encode(utf8_text, 'hex').decode()  # 将字节字符串转换为十六进制表示
        st.write(f"hex:{hex_text}")
        body = body % hex_text
        #st.write(body)
        components.html(body,height=200,)
elif models == "自动连打":
    models2 = st.selectbox("", ("EVM系", "COSMOS系"))
    if models2 == "EVM系":
        text_data = st.text_input(f"data示例:{text}")
        RPC = st.radio("Rpc_url：", ("BSC","Polygon","OP","ETH","自定义"))
        rpc=""
        if RPC == "ETH":
            rpc="https://rpc.ankr.com/eth"
        elif RPC == "BSC":
            rpc="https://rpc.ankr.com/bsc"
        elif RPC == "Polygon":
            rpc = "https://rpc.ankr.com/polygon"
        elif RPC == "OP":
            rpc = "https://rpc.ankr.com/optimism"
        elif RPC == "自定义":
            rpc=st.text_input(f"Rpc_url：")
        st.text(rpc)
        nums = st.text_input(f"连打数量：")
        try:
            nums = int(nums)
        except:
            nums =1
        keys = []
        keys_0 = st.text_area(f"私钥,支持多个钱包同时打，回车隔开多个私钥，一行一个：")
        try:
            keys_0 = keys_0.split("\n")
            address=[]
            for i in keys_0:
                try:
                    owner = Web3.toChecksumAddress(from_key(i))
                    keys.append(i)
                    address.append(owner)
                except:
                    pass
            st.write(address)
        except:
            pass

        utf8_text = str(text_data).encode('utf-8')  # 将文本转换为UTF-8编码的字节字符串
        hex_text = '0x' + codecs.encode(utf8_text, 'hex').decode()  # 将字节字符串转换为十六进制表示
        st.write(f"hex:{hex_text}")

        go = st.button("开始")

        if go:
            if keys_0 == "":
                st.write("请输入私钥")
            else:
                w3 = Web3(Web3.HTTPProvider(rpc))
                chainid = get_chainid(rpc)

                for i in range(nums):
                    try:
                        for okey in keys:
                            try:
                                owner = Web3.toChecksumAddress(from_key(okey))
                                to = owner

                                nonce = w3.eth.getTransactionCount(owner)

                                tx_data = hex_text
                                payload = {
                                    'from': owner,
                                    'to': owner,
                                    'data': tx_data
                                }
                                estimation = w3.eth.estimateGas(payload)
                                estimation += 61000
                                gasprice = int(w3.eth.gasPrice * 1.1)
                                payload = {
                                    'from': owner,
                                    'to': owner,
                                    'data': tx_data,
                                    'nonce': nonce,
                                    'gas': estimation,
                                    'gasPrice': gasprice,
                                    'chainId': chainid
                                }
                                signed_tx = w3.eth.account.signTransaction(payload, okey)
                                tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
                                if len(keys) <= 2:
                                    receipt = w3.eth.waitForTransactionReceipt(tx_hash)
                                txid = w3.toHex(tx_hash)
                                st.write(i,"完成",txid)
                            except Exception as e:
                                st.write("错误:", e)
                                wait(5)
                    except Exception as e:
                        st.write("错误:",e)
                        wait(5)
    elif models2 == "COSMOS系":
        text='data:,{"op":"mint","amt":10000,"tick":"cias","p":"cia-20"}'
        text_data = st.text_input(f"data示例:{text}")
        memo=""
        if text_data != "":
            memo = to_base64(text_data)
            st.write(memo)

        RPC = st.radio("链：", ("COSMOS", "TIA"))
        rpc = ""
        if RPC == "COSMOS":
            rest = "https://cosmos-rest.publicnode.com"
            rpc = "https://cosmos-rpc.publicnode.com:443"
            coins = "uatom"
            hrp = "cosmos"
            gas=80000
            fee=2500
        elif RPC == "TIA":
            rest = "https://celestia-rest.publicnode.com"
            rpc = "https://celestia-rpc.publicnode.com:443"
            coins = "utia"
            hrp = "celestia"
            gas=80000
            fee=500
        RPC2 = st.radio("rpc：", ("自动", "自定义"))
        GAS = st.radio("GAS：", ("默认", "自定义"))
        if GAS == "自定义":
            gas = st.text_input(f"gas：")
            fee = st.text_input(f"fee：")
            try:
                gas = int(gas)
                fee= int(fee)
            except:
                pass
        if RPC2 == "自定义":
            rpc = RPC2
        st.write("使用rpc",rpc)
        keys = st.text_input(f"私钥：")
        nums = st.text_input(f"连打数量,别打太多容易挂：")
        try:
            nums = int(nums)
        except:
            nums = 1
        go=st.button("开始")
        if go:
            for i in range(nums):
                client = HTTPClient(api=rest)
                account = Account(private_key=keys, hrp=hrp)
                client.load_account_data(account=account)
                st.write("地址:", account.address)
                try:
                    nonce = account.next_sequence
                    if RPC == "COSMOS":
                        tx = Transaction(account=account,gas=gas,memo=memo)
                    elif RPC == "TIA":
                        tx = Transaction(account=account, gas=gas, memo=memo, chain_id='celestia')
                    tx.set_fee(amount=fee,denom=coins)
                    tx.add_msg(tx_type='transfer',sender=account,receipient=account.address,amount=1,denom=coins,)
                    tx_bytes = tx.get_tx_bytes_as_string()
                    pushable_tx = json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "broadcast_tx_sync",
                            "params": {
                                "tx": tx_bytes
                            }
                        }
                    )
                    r = httpx.post(rpc, data=pushable_tx)
                    st.write(i,"完成",r.text)
                    wait(2)
                except Exception as e:
                    st.write("错误",e)
                    wait(1)



