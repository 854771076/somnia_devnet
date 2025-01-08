import requests
from web3 import Web3
from loguru import logger
import json, os
import glob
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
from fake_useragent import UserAgent
from eth_account.messages import encode_defunct
from curl_cffi.requests import Session
from datetime import timedelta, datetime
import time
from numpy import nan
import threading
from functools import *
from datetime import datetime,timedelta
from apscheduler.schedulers.blocking import BlockingScheduler
import random
ua = UserAgent()
# 写一个类装饰器，用于装饰返回对象是response的函数,用于检查请求状态和请求的重试
def check_request_status(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        for _ in range(3):
            try:
                response,is_retry = func(*args, **kwargs)
                if is_retry:
                    continue
                if response.status_code == 200:
                    return response
                else:
                    logger.debug(f"请求失败，状态码：{response.status_code}")
            except Exception as e:
                logger.exception(f"请求失败，错误信息：{e}")
            time.sleep(5)
        return None
    return wrapper

class Somnia_TestNet_Bot:
    
    def __init__(
        self,
        wallet_path="./wallets.csv",
        contract_path="./contract",
        rpc_url="https://dream-rpc.somnia.network/",
        proxy: str = "http://xxx",
    ):
        self.headers={
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Origin': 'https://devnet.somnia.network',
            'Pragma': 'no-cache',
            'Referer': 'https://devnet.somnia.network/?_gl=1*ifzcel*_ga*NDk1MDgxOTQ3LjE3MzU2MDc5ODE.*_ga_VRC3ZXBRT1*MTczNTYxNDI0OC4zLjEuMTczNTYxNDI1MC41OC4wLjA.',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            # 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        self.rpc_url = rpc_url
        self.wallet_path = wallet_path
        self.contract_path = contract_path
        self.web3 = Web3(Web3.HTTPProvider(rpc_url))
        self._lock=threading.Lock()
        self.contracts = {}
        # 检查连接是否成功
        if not self.web3.is_connected():
            raise Exception("无法连接到 Somnia 节点")
        self.chain_id = 50311
        # 初始化钱包
        self.wallets = []
        self.sessions = {}      
        self.get_contract()
        logger.success(f"初始化智能合约成功：{self.contracts.keys()}")
        self.get_wallets()
        logger.success(f"初始化钱包成功-钱包数量：{len(self.wallets)}")
        self.proxies = {
            "http": proxy,
            "https": proxy,
        }
        self.init_wallets()
    def get(self, address, url, params=None,retries=3):
        #添加重试机制
        for i in range(retries):
            try:
                response = self.get_session(address).get(url, params=params)
                if response.status_code == 200:
                    return response
                else:
                    logger.error(f"{address}-请求失败-{response.status_code}")
                    time.sleep(3)
            except Exception as e:
                logger.error(f"{address}-请求失败-{e}")
                time.sleep(3)

    def post(self, address, url, json=None,retries=3):
        for i in range(retries):
            try:
                response = self.get_session(address).post(url, json=json)
                if response.status_code == 200:
                    return response
                else:
                    logger.error(f"{address}-请求失败-{response.status_code}")
                    time.sleep(3)
            except Exception as e:
                logger.error(f"{address}-请求失败-{e}")
                time.sleep(3)
    @check_request_status
    def login(self,session,wallet):
        message = '{"onboardingUrl":"https://quest.somnia.network"}'
        signature = self.get_sign(wallet,message)

        json_data = {
            'signature': signature,
            'walletAddress': wallet['address'],
        }
        try:
            response = session.post('https://quest.somnia.network/api/auth/onboard',json=json_data)
            token= response.json().get('token')
            if token:
                session.headers.update({"Authorization": f"Bearer {token}"})
                logger.success(f"{wallet.get('address')}登录成功")
            else:
                logger.error(f"{wallet.get('address')}登录失败")
        except Exception as e:
            logger.error(f"{wallet.get('address')}登录失败-{e}")
        return response,False
    def get_session(self,wallet):
        '''
        获取session
        '''
        session = Session(headers=self.headers,proxies=self.proxies,impersonate="chrome99")
        session.headers.update({"User-Agent": ua.chrome})
        self.login(session,wallet)
        return session
    def get_one_other_wallet(self,wallet)->dict:
        '''
        获取一个随机的其他钱包
        '''
        other_wallets = [w for w in self.wallets if w != wallet and w.get('init') ]
        return random.choice(other_wallets)
    def faucet(self,session,wallet):
        """
        水龙头
        :return:
        """
        json_data = {
            'address': wallet['address'],
        }
        try:
            response = session.post('https://devnet.somnia.network/api/faucet', json=json_data)
            data=response.json()
            if data.get('success'):
                if wallet.get('init')!=True:
                    wallet['init']=True
                    self.save_wallets()
                logger.success(f"{wallet.get('address')}-水龙头成功")
            else:
                logger.error(f"{wallet.get('address')}-{data.get('msg')}")
        except Exception as e:
            logger.error(f"{wallet.get('address')}-{e}")
        return response,False

    def send_ETH(self,wallet,to_address,amount_huiman=0.1):
        """
        发送ETH到其他钱包
        """
        privatekey=wallet['private_key']
        amount=Web3.to_wei(amount_huiman, "ether")
        # 发送ETH到其他地址
        tx = {
            "to": to_address,
            "value": amount,
            "gas": 21000,
            "gasPrice": self.web3.eth.gas_price,
            "nonce": self.web3.eth.get_transaction_count(
                self.web3.eth.account.from_key(privatekey).address
            ),
            "chainId": self.chain_id,
        }
        signed_tx = self.web3.eth.account.sign_transaction(tx, privatekey)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
        return tx_hash.hex()
    
    def send_TTL_to_other_wallet(self,wallet,amount_huiman=0.1):
        '''
        发送TTL到其他钱包
        '''
        other_wallets = self.get_one_other_wallet(wallet)
        try:
            tx_hash = self.send_ETH(wallet,other_wallets['address'],amount_huiman)

            logger.success(f"{wallet.get('address')}-发送TTL到{other_wallets.get('address')}成功-{tx_hash}")
            return tx_hash
        except Exception as e:
            logger.error(f"{wallet.get('address')}-发送TTL到{other_wallets.get('address')}失败-{e}")
    def receive_TTL_to_other_wallet(self,wallet,amount_huiman=0.1):
        '''
        发送TTL到其他钱包
        '''
        other_wallets = self.get_one_other_wallet(wallet)
        try:
            tx_hash = self.send_ETH(other_wallets,wallet['address'],amount_huiman)

            logger.success(f"{other_wallets.get('address')}-发送TTL到{wallet.get('address')}成功-{tx_hash}")
            return tx_hash
        except Exception as e:
            logger.error(f"{other_wallets.get('address')}-发送TTL到{wallet.get('address')}失败-{e}")
    ### 转账任务
    @check_request_status
    def check_balance(self,session,wallet):
        json_data = {
            'questId': 14,
        }
        try:
            response = session.post('https://quest.somnia.network/api/onchain/native-token',json=json_data)
            if response.json().get('success'):
                logger.success(f"{wallet.get('address')}-验证余额成功")
            else:
                logger.error(f"{wallet.get('address')}-验证余额失败")
                return response,True
        except Exception as e:
            logger.error(f"{wallet.get('address')}-验证余额失败-{e}")
        return response,False
    @check_request_status
    def check_send_tx(self,session,wallet, send_txn):
        json_data = {
            'questId': 15,
            'txHash': send_txn
        }
        try:
            response = session.post('https://quest.somnia.network/api/onchain/tx-hash', json=json_data)
            if response.json().get('success'):
                logger.success(f'{wallet.get('address')}-验证转账成功')
            else:
                logger.error(f'{wallet.get('address')}-验证转账失败')
                return response,True
        except Exception as e:
            logger.error(f'{wallet.get('address')}-验证转账失败-{e}')
        return response,False
    @check_request_status
    def check_receive_tx(self,session,wallet, receive_txn):
        json_data = {
            'questId': 16,
            'txHash': receive_txn
        }
        try:
            response = session.post('https://quest.somnia.network/api/onchain/tx-hash', json=json_data)
            if response.json().get('success'):
                logger.success(f'{wallet.get('address')}-验证收款成功')
            else:
                logger.error(f'{wallet.get('address')}-验证收款失败')
                return response,True
        except Exception as e:
            logger.error(f'{wallet.get('address')}-验证收款失败-{e}')
        return response,False
    ###
    def approve(
            self,
            wallet,
            token_name="USDT",
            address="0x8812d810EA7CC4e1c3FB45cef19D6a7ECBf2D85D",
            amount=100000000000000,
        ):
        """
        授权
        :return:
        """
        assert (
            token_name in self.contracts.keys()
        ), f"token_name is not in {list(self.contracts.keys())}"
        privatekey=wallet['private_key']
        # 实例化合约
        contract = self.contracts[token_name]
        # 获取代币精度
        decimals = contract.functions.decimals().call()
        # 计算授权数量
        amount = int(amount * 10**decimals)
        # 地址信息
        address = Web3.to_checksum_address(address)
        # 授权并发送交易
        tx = contract.functions.approve(address, amount).build_transaction(
            {
                "from": self.web3.eth.account.from_key(privatekey).address,
                "nonce": self.web3.eth.get_transaction_count(
                    self.web3.eth.account.from_key(privatekey).address
                ),
                "gasPrice": self.web3.eth.gas_price,
                "chainId": self.chain_id,
            }
        )
        signed_tx = self.web3.eth.account.sign_transaction(tx, privatekey)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        return tx_hash.hex()
    def transfer_task(
            self,
            session,
            wallet,
    ):
        if not wallet.get('transfer_task'):
            send_tx=self.send_TTL_to_other_wallet(wallet)
            receive_tx=self.receive_TTL_to_other_wallet(wallet)
            self.check_balance(session,wallet)
            if  send_tx:
                resp1=self.check_send_tx(session,wallet,send_tx)
            if  receive_tx:
                resp2=self.check_receive_tx(session,wallet,receive_tx)
            if resp1.json().get('success') and resp2.json().get('success'):
                wallet['transfer_task']=True
                self.save_wallets()
    def get_sign(self, wallet, msg):
        # 账户信息
        private_key = wallet["private_key"]
        address = wallet["address"]
        # 使用web3.py编码消息
        message_encoded = encode_defunct(text=msg)
        # 签名消息
        signed_message = self.web3.eth.account.sign_message(
            message_encoded, private_key=private_key
        ).signature.hex()
        if '0x' not in signed_message:
            signed_message = '0x' + signed_message
        # 打印签名的消息
        return signed_message

    def generate_and_save_wallet(self):
        # 生成新账户
        account = self.web3.eth.account.create()
        # 获取地址和私钥
        address = account.address
        try:
            private_key = account.privateKey.hex()
        except:
            private_key = account._private_key.hex()
        # 将地址和私钥保存到 JSON 文件
        wallet_info = {"address": address, "private_key": private_key}
        with self._lock:
            self.wallets.append(wallet_info)
        logger.success(f"创建钱包成功-{address}")

    def load_contract(self, filename: str):
        # 从 JSON 文件中读取钱包信息
        with open(filename, "r") as file:
            contract_info = json.load(file)
        return contract_info

    def get_wallets(self):
        self.wallets = []
        try:
            wallets_df= pd.read_csv(os.path.join(self.wallet_path),encoding='utf8')
        # 抛出编码错误
        except UnicodeDecodeError:
            # 尝试使用 latin-1 编码
            wallets_df= pd.read_csv(os.path.join(self.wallet_path), encoding='gbk')
        except Exception as e:
            logger.error(f"读取钱包文件失败 {e}")
            return []
        wallets_df['address']=wallets_df['address'].apply(lambda x: self.web3.to_checksum_address(x))
        wallets_df=wallets_df.fillna(False)
        self.wallets =wallets_df.to_dict(orient='records')
        return self.wallets 
    # 保存钱包
    def save_wallets(self):
        with self._lock:
            wallets_df= pd.DataFrame(self.wallets)
            wallets_df.to_csv(os.path.join(self.wallet_path), index=False,encoding='utf8')
            logger.success(f"钱包信息已保存 {self.wallet_path}")
    def get_contract(self):
        self.contracts = {}
        contracts_list = glob.glob(os.path.join(self.contract_path, "*"))
        # 使用线程池来并发加载钱包
        for contract_path in contracts_list:
            contract_info = self.load_contract(contract_path)
            name = contract_info.get("name")
            contract_address = contract_info.get("address")
            abi = contract_info.get("abi")
            contract_address = self.web3.to_checksum_address(contract_address)
            contract = self.web3.eth.contract(address=contract_address, abi=abi)
            self.contracts[name] = contract

    def create_wallets(self, num=1):
        # 使用线程池来并发生成钱包
        with ThreadPoolExecutor(max_workers=20) as executor:
            for i in range(num):
                executor.submit(self.generate_and_save_wallet)
        self.save_wallets()

    def get_contract_transaction_gas_limit(self, func, address):
        # 估算所需的 gas
        gas_estimate = func.estimate_gas({"from": address})
        # 获取当前 gas 价格
        gas_price = self.web3.eth.gas_price
        # 获取账户余额
        balance = self.web3.eth.get_balance(address)
        # 计算总费用
        total_cost = gas_estimate * gas_price
        # 判断 gas 或转账是否合理
        if total_cost > balance:
            ValueError("gas不足改日领水后重试")
        # 返回估算的 gas
        return gas_estimate
    # 查询所有钱包余额并输出
    def get_wallet_balance(self,wallet):
        address = wallet["address"]
        balance = self.web3.eth.get_balance(address)/1e18
        return balance
    # 多线程查询所有钱包余额并输出
    def get_wallets_balance(self):
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(self.get_wallet_balance, wallet) for wallet in self.wallets
            ]
            for future in as_completed(futures):
                try:
                    data = future.result()
                except Exception as e:
                    logger.error(f"Error get_wallet_balance wallet: {e}")
        
    def init_wallet(self,wallet):
        session=self.get_session(wallet)
        try:
            self.faucet(session,wallet)
        except Exception as e:
            logger.exception(f"{wallet.get('address')}-{e}")
    def init_wallets(self,max_workers=20):
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(self.init_wallet, wallet) for wallet in self.wallets if not wallet.get('init')
            ]
            for future in as_completed(futures):
                try:
                    data = future.result()
                except Exception as e:
                    logger.exception(f"Error init_wallet wallet: {e}")

    def daily_task(self, wallet):
        try:
            address=wallet['address']
            session=self.get_session(wallet)
            if not wallet.get('init'):
                self.init_wallet(wallet)
            else:
                self.faucet(session,wallet)
            
           
            # try:
            #     self.transfer_task(session,wallet)
            # except Exception as e:
            #     logger.exception(f"{wallet.get('address')}-{e}")
            try:
                self.mint_SUSDT(wallet)
            except Exception as e:
                logger.exception(f"{wallet.get('address')}-{e}")
            try:
                self.mint_WSTT(wallet)
            except Exception as e:
                logger.exception(f"{wallet.get('address')}-{e}")
            try:
                self.approve_SUSDT(wallet,'0xDc66B15A4aEaDBea5F64Cf0E611E41Ab422d06BA')
            except Exception as e:
                logger.exception(f"{wallet.get('address')}-{e}")
            try:
                self.approve_WSTT(wallet,'0xDc66B15A4aEaDBea5F64Cf0E611E41Ab422d06BA')
            except Exception as e:
                logger.exception(f"{wallet.get('address')}-{e}")
            try:
                self.swap(wallet)
            except Exception as e:
                logger.exception(f"{wallet.get('address')}-{e}")
        except Exception as e:
            logger.exception(f"{wallet.get('address')}-{e}")
    def mint_nft(self, wallet):

        private_key=wallet['private_key']
        to = Web3.to_checksum_address(wallet["address"])
        contract = self.contracts['ERC-721']
        func = contract.functions.mint(1)
        tx = func.build_transaction(
            {
                "from": to,
                "nonce": self.web3.eth.get_transaction_count(
                    to
                ),
                "gasPrice": self.web3.eth.gas_price,
                "chainId": self.chain_id,
            }
        )
        signed_tx = self.web3.eth.account.sign_transaction(tx, private_key)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status:
            logger.success(f'{to}-MINT成功-{tx_hash.hex()}')
        else:
            logger.error(f'{to}-MINT失败！')
    def mint_WSTT(self, wallet):

        private_key=wallet['private_key']
        to = Web3.to_checksum_address(wallet["address"])
        contract = self.contracts['WSTT']
        func = contract.functions.mint(to,Web3.to_wei(100000000,'ether'))
        tx = func.build_transaction(
            {
                "from": to,
                "nonce": self.web3.eth.get_transaction_count(
                    to
                ),
                "gasPrice": self.web3.eth.gas_price,
                "chainId": self.chain_id,
            }
        )
        signed_tx = self.web3.eth.account.sign_transaction(tx, private_key)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status:
            logger.success(f'{to}-MINT WSTT成功-{tx_hash.hex()}')
        else:
            logger.error(f'{to}-MINT WSTT失败！')
    def mint_SUSDT(self, wallet):

        private_key=wallet['private_key']
        to = Web3.to_checksum_address(wallet["address"])
        contract = self.contracts['SUSDT']
        func = contract.functions.mint(to,int(100000000*1e6))
        tx = func.build_transaction(
            {
                "from": to,
                "nonce": self.web3.eth.get_transaction_count(
                    to
                ),
                "gasPrice": self.web3.eth.gas_price,
                "chainId": self.chain_id,
            }
        )
        signed_tx = self.web3.eth.account.sign_transaction(tx, private_key)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status:
            logger.success(f'{to}-MINT SUSDT成功-{tx_hash.hex()}')
        else:
            logger.error(f'{to}-MINT SUSDT失败！')
    def approve_SUSDT(self, wallet,to):
        """
        授权代币
        :param wallet:
        :param token_name:
        :return:
        """
        private_key=wallet['private_key']
        address = Web3.to_checksum_address(wallet["address"])
        to=Web3.to_checksum_address(to)
        contract = self.contracts['SUSDT']
        # 获取余额
        balance = contract.functions.balanceOf(address).call()
        func = contract.functions.approve(to,balance)
        tx = func.build_transaction(
            {
                "from": address,
                "nonce": self.web3.eth.get_transaction_count(
                    address
                ),
                "gasPrice": self.web3.eth.gas_price,
                "chainId": self.chain_id,
            }
        )
        signed_tx = self.web3.eth.account.sign_transaction(tx, private_key)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status:
            logger.success(f'{to}-approve SUSDT成功-{tx_hash.hex()}')
        else:
            logger.error(f'{to}-approve SUSDT失败！')
    def approve_WSTT(self, wallet,to):
        """
        授权代币
        :param wallet:
        :param token_name:
        :return:
        """
        private_key=wallet['private_key']
        address = Web3.to_checksum_address(wallet["address"])
        to=Web3.to_checksum_address(to)
        contract = self.contracts['WSTT']
        # 获取余额
        balance = contract.functions.balanceOf(address).call()
        func = contract.functions.approve(to,balance)
        tx = func.build_transaction(
            {
                "from": address,
                "nonce": self.web3.eth.get_transaction_count(
                    address
                ),
                "gasPrice": self.web3.eth.gas_price,
                "chainId": self.chain_id,
            }
        )
        signed_tx = self.web3.eth.account.sign_transaction(tx, private_key)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status:
            logger.success(f'{to}-approve SUSDT成功-{tx_hash.hex()}')
        else:
            logger.error(f'{to}-approve SUSDT失败！')
    def swap(self, wallet,balance=Web3.to_wei(1000,'ether')):
        """
        交换代币
        :param wallet:
        :param token_name:
        :return:
        """
        private_key=wallet['private_key']
        address = Web3.to_checksum_address(wallet["address"])
        contract = self.contracts['router']
        tokenIn=self.contracts['WSTT'].address
        tokenOut=self.contracts['SUSDT'].address
        fee=3000
        recipient=address
        amountIn=balance
        amountOutMinimum=0
        sqrtPriceLimitX96=0
        func = contract.functions.exactInputSingle(
           {
            'tokenIn':tokenIn,
            'tokenOut':tokenOut,
            'fee':fee,
            'recipient':recipient,
            'amountIn':amountIn,
            'amountOutMinimum':amountOutMinimum,
            'sqrtPriceLimitX96':sqrtPriceLimitX96
           }
        )
        tx = func.build_transaction(
            {
                "from": address,
                "nonce": self.web3.eth.get_transaction_count(
                    address
                ),
                "gasPrice": self.web3.eth.gas_price,
                "chainId": self.chain_id,
            }
        )
        signed_tx = self.web3.eth.account.sign_transaction(tx, private_key)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status:
            logger.success(f'{address}- WSTT->SUSDT交换成功-{tx_hash.hex()}')
        else:
            logger.error(f'{address}- WSTT->SUSDT失败！')
    def do_daily_tasks(self, max_workers=20):
        try:
            self.get_wallets()
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [
                    executor.submit(self.daily_task, wallet) for wallet in self.wallets
                ]
                for future in as_completed(futures):
                    try:
                        data = future.result()
                    except Exception as e:
                        logger.error(f"Error daily_task wallet: {e}")

            self.get_wallets_balance()
        except Exception as e:
            logger.error(f"{e}")

if __name__ == "__main__":
    bot = Somnia_TestNet_Bot()
    # bot.approve_WSTT(bot.wallets[0],'0xdc66b15a4aeadbea5f64cf0e611e41ab422d06ba')
    # bot.swap(bot.wallets[0])
    # bot.mint_nft(bot.wallets[0])
    # bot.create_wallets(1000)
    scheduler = BlockingScheduler()
    # session=bot.get_session(bot.wallets[0])
    # bot.transfer_task(session,bot.wallets[0])
    bot.do_daily_tasks()
    # 执行时间间隔24小时30分后执行
    scheduler.add_job(bot.do_daily_tasks, "interval", hours=24,minutes=30)
    # 启动调度器
    scheduler.start()
