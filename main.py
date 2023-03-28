from PyQt6 import QtWidgets
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from Ui_gui import Ui_MainWindow
from Ui_login import Ui_Login
import requests
import asyncio
import aiohttp
import string
import json
import hashlib
import random
import time
import configparser
import shelve
#機器瑪
import uuid
import wmi
class register():
    def __init__(self):
        self.s = wmi.WMI()
    # cpu 序列号
    def get_CPU_info(self):
        cpu = []
        cp = self.s.Win32_Processor()
        for u in cp:
            cpu.append(
                {
                    "Name": u.Name,
                    "Serial Number": u.ProcessorId,
                    "CoreNum": u.NumberOfCores
                }
            )
        #   print(":::CPU info:", json.dumps(cpu))
        return cpu
 
    # 硬盘序列号
    def get_disk_info(self):
        disk = []
        for pd in self.s.Win32_DiskDrive():
            disk.append(
                {
                    "Serial": self.s.Win32_PhysicalMedia()[0].SerialNumber.lstrip().rstrip(),  # 获取硬盘序列号，调用另外一个win32 API
                    "ID": pd.deviceid,
                    "Caption": pd.Caption,
                    "size": str(int(float(pd.Size) / 1024 / 1024 / 1024)) + "G"
                }
            )
        #   print(":::Disk info:", json.dumps(disk))
        return disk
 
    # mac 地址（包括虚拟机的）
    def get_network_info(self):
        network = []
        for nw in self.s.Win32_NetworkAdapterConfiguration():  # IPEnabled=0
            if nw.MACAddress != None:
                network.append(
                    {
                        "MAC": nw.MACAddress,  # 无线局域网适配器 WLAN 物理地址
                        "ip": nw.IPAddress
                    }
                )
        #    print(":::Network info:", json.dumps(network))
        return network
 
    # 主板序列号
    def get_mainboard_info(self):
        mainboard = []
        for board_id in self.s.Win32_BaseBoard():
            mainboard.append(board_id.SerialNumber.strip().strip('.'))
        return mainboard
    #拼接函數
    def getCombinNumber(self):
        a = self.get_network_info()
        b = self.get_CPU_info()
        c = self.get_disk_info()
        d = self.get_mainboard_info()
        machinecode_str = ""
        machinecode_str = machinecode_str + a[0]['MAC'] + b[0]['Serial Number'] + c[0]['Serial'] + d[0]
        selectindex = [15, 31, 34, 39, 44, 48]
        macode = ""
        for i in selectindex: #根据字符串位数筛选部分字符
            macode = macode + machinecode_str[i]
        return macode
    def gen_machineCode(self):
        machine_code = self.getCombinNumber()
        machine_code_hash = hashlib.sha256(str(machine_code).encode('utf-8')).hexdigest()
        return machine_code_hash
    def checkregister(self):
        machineCode = self.gen_machineCode()
        httpregister = requests.get("https://raw.githubusercontent.com/130347665/Eccs-Search-Pyqt6/master/reistercode.txt").text.split("\n")
        print(machineCode)
        print(httpregister)
        try:
            httpregister.index(machineCode)
            return True
        except ValueError as e:
            return False
            
        

#Load ini
config = configparser.ConfigParser()
config.read('config.ini')
class Eccs():
    def __init__(self,idNo,userId,userPwd,lang,userType):
        self.idNo = idNo
        self.userId = userId
        self.userPwd = userPwd
        self.lang = lang
        self.userType = userType
        self.userId2 = "{}_{}_{}".format(userType,idNo,userId)
        try:
            self.token = self.login()
        except Exception as e:
            QMessageBox.information(None,"Error","登入失敗")
            return
    def login(self):
        timestamp = str(int(time.time()))
        letters = string.ascii_lowercase + string.digits
        salt = ''.join(random.choice(letters) for i in range(12))
        sign = salt + hashlib.md5(("" + salt + timestamp + "+xH9x!&").encode('utf-8')).hexdigest()
        urlToken = "https://eccs.tradevan.com.tw/APECCS/ezway/auth/token"
        headersToken = {"Sign": sign,
                        "Timestamp": timestamp,
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
                        "Content-Type": "application/json;charset=UTF-8"}
        dataToken = {"lang": "TW"}
        respToken = requests.post(urlToken, headers=headersToken, data=json.dumps(dataToken)).text
        jsonToken = json.loads(respToken)
        LoginUrl = "https://eccs.tradevan.com.tw/APECCS/ezway/login"
        LoginHeaders = {"Sign": sign,
                        "Timestamp": timestamp,
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
                        "Content-Type": "text/html; charset=UTF-8",
                        "Authorization": "Bearer "+jsonToken['data']['token']
                        }
        LoginData={"idNo": self.idNo,
                "lang": "TW",
                "userId": self.userId,
                "userPwd": self.userPwd,
                "userType": "CUSTOMER"
                }
        LoginResp=json.loads(requests.post(LoginUrl,headers=LoginHeaders,data=json.dumps(LoginData)).text)
        LoginToken = LoginResp['data']['token']
        return LoginToken

    def divide_list(self,list_, chunk_size=999):
        for i in range(0, len(list_), chunk_size):
            yield list_[i:i+chunk_size]
    def EccsCheckID(self,userIDlist):
        timestamp = str(int(time.time()))
        letters = string.ascii_lowercase + string.digits
        salt = ''.join(random.choice(letters) for i in range(12))
        sign = salt + hashlib.md5(("" + salt + timestamp + "+xH9x!&").encode('utf-8')).hexdigest()

        url = "https://eccs.tradevan.com.tw/APECCS/ezway/v1/realname/id"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
            "Authorization": "Bearer " + self.token,
            "Sign": sign,
            "Timestamp": timestamp,
            "Content-Type": "application/json;charset=UTF-8"
        }
        ret = []
        for chunk in self.divide_list(userIDlist):
            datajson = {"lang": self.lang,
                    "idNo": chunk,
                    "userId": self.userId2}
            resp2 = requests.post(url, headers=headers, data=json.dumps(datajson)).text
            jsonload = json.loads(resp2)
            for i in range(0, len(jsonload['data'])):
                id = jsonload['data'][i]['idNo']
                verifyStatus = jsonload['data'][i]['verifyStatus']
                ret.append([id,verifyStatus])
        return ret
    def EccsCheckPhone(self,userIDlist):
        timestamp = str(int(time.time()))
        letters = string.ascii_lowercase + string.digits
        salt = ''.join(random.choice(letters) for i in range(12))
        sign = salt + hashlib.md5(("" + salt + timestamp + "+xH9x!&").encode('utf-8')).hexdigest()

        url = "https://eccs.tradevan.com.tw/APECCS/ezway/v1/realname/tel-no"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
            "Authorization": "Bearer " + self.token,
            "Sign": sign,
            "Timestamp": timestamp,
            "Content-Type": "application/json;charset=UTF-8"
        }
        ret = []
        for chunk in self.divide_list(userIDlist):
            datajson = {"lang": self.lang,
                    "telNo": chunk,
                    "userId": self.userId2}
            resp2 = requests.post(url, headers=headers, data=json.dumps(datajson)).text
            print(resp2)
            jsonload = json.loads(resp2)
            for i in range(0, len(jsonload['data'])):
                id = jsonload['data'][i]['telNo']
                verifyStatus = jsonload['data'][i]['verifyStatus']
                ret.append([id,verifyStatus])
        return ret
    async def EccsCheckPreverify(self,hawbNo): #預先委任確認查詢(簡易)
        await asyncio.sleep(0.3)
        timestamp = str(int(time.time()))
        letters = string.ascii_lowercase + string.digits
        salt = ''.join(random.choice(letters) for i in range(12))
        sign = salt + hashlib.md5(("" + salt + timestamp + "+xH9x!&").encode('utf-8')).hexdigest()

        url = "https://eccs.tradevan.com.tw/APECCS/ezway/v3/realname/preverify-result"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
            "Authorization": "Bearer " + self.token,
            "Sign": sign,
            "Timestamp": timestamp,
            "Content-Type": "application/json;charset=UTF-8"
        }
        ret = []
        async with aiohttp.ClientSession() as session:
            datajson = {
                    "authorizeStatus":"A",
                    "brokerBan":self.idNo,
                    "declType": "TX",
                    "hawbNo": hawbNo,
                    "lang": self.lang,
                    "status":"A",
                    "userId": self.userId2}
            async with session.post(url, headers=headers, data=json.dumps(datajson)) as resp:
                resp_text = await resp.text()
                return resp_text
                # retJson = json.loads(resp_text)
                # print(retJson)
                # print(retJson['data'])
                # for i in range(0, len(retJson['data'])):
                #     id = retJson['data'][i]['telNo']
                #     verifyStatus = retJson['data'][i]['verifyStatus']
                #     ret.append([id, verifyStatus])
        #return ret
    async def runEccsCheckPreverify(self,preverifyList):
        task_list = []
        ret_list = []
        # for hawb in preverifyList:
        #     task = asyncio.create_task(self.EccsCheckPreverify(hawb))
        #     task_list.append(task)
        # done, pending = await asyncio.wait(task_list, timeout=None)
        tasks = [asyncio.create_task(self.EccsCheckPreverify(hawb)) for hawb in preverifyList]
        done = await asyncio.gather(*tasks)
        # 得到执行结果
        for done_task,hawbNo in zip(done,preverifyList):
            ret_json = json.loads(done_task)
            #print(done_task)
            #print(ret_json)
            if ret_json['data'] == None:
                ret_list.append([hawbNo,'查無資料'])
            elif (ret_json['data'][0]['authorizeReply'] == None):
                ret_list.append([hawbNo,'未核准'])
            elif (ret_json['data'][0]['authorizeReply'] == '00'):
                ret_list.append([hawbNo,'核准'])
            elif (ret_json['data'][0]['authorizeReply'] == '30'):
                ret_list.append([hawbNo,'移民署回復居留證無效'])
            elif (ret_json['data'][0]['authorizeReply'] == '31'):
                ret_list.append([hawbNo,'報單號碼格式錯誤'])
            elif (ret_json['data'][0]['authorizeReply'] == '32'):
                ret_list.append([hawbNo,'報關箱號錯誤'])
            elif (ret_json['data'][0]['authorizeReply'] == '33'):
                ret_list.append([hawbNo,'其他'])
            elif (ret_json['data'][0]['authorizeReply'] == '99'):
                ret_list.append([hawbNo,'已接收到資料(僅限居留證)'])
            else:
                ret_list.append([hawbNo,'未知'])
            print(f"{time.time()} 得到执行结果 {done_task}")
        #print(ret_list)
        return ret_list
class LoginWindow(QtWidgets.QMainWindow,Ui_Login):
    def __init__(self):
        super(LoginWindow,self).__init__()
        self.setupUi(self)
        self.pushButton_2.clicked.connect(self.login)
        try:
            with shelve.open('EccsSearch') as registry:
                # 讀取帳號密碼
                username = registry['username']
                password = registry['password']
                print(f'Username: {username}')
                print(f'Password: {password}')
            self.lineEdit.setText(username)
            self.lineEdit_2.setText(password)
                
        except KeyError:
            print('No username or password found.')
        self.lineEdit_2.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.show()
        
    def login(self): 
        self.username = self.lineEdit.text()
        self.password = self.lineEdit_2.text()

                # 開啟註冊表
        with shelve.open('EccsSearch') as registry:
            # 寫入帳號密碼
            registry['username'] = self.username
            registry['password'] = self.password
        payload = {'username':self.username,'password':self.password}
        #帳號 密碼 驗證規則 大於6碼 小於12碼 且包含英文數字 不包含特殊符號
        if len(self.username) < 4 or len(self.username) > 12 or len(self.password) < 4 or len(self.password) > 12:
            QMessageBox.warning(self, "錯誤", "帳號密碼長度錯誤 請輸入4~12碼 ")
            return
        elif not self.username.isalnum() or not self.password.isalnum():
            QMessageBox.warning(self, "錯誤", "帳號密碼不可包含特殊符號")
            return
        else:
            req = requests.post('http://165.22.99.159/user/login',data=payload).json()
            if req['code'] == 200:
                self.hide()
                self.window = MyWindow()
                self.window.show()
            elif (req['code'] == 404):
                QMessageBox.warning(self, "錯誤", "登入失敗")
class MyWindow(QtWidgets.QMainWindow,Ui_MainWindow):
    
    def __init__(self):
        super(MyWindow,self).__init__()
        self.setupUi(self)                      #这个是我们生成的py里面的一个函数。就是用于绘制界面的。
        self.pushButton.clicked.connect(self.search)
        self.initConfig()
        #全選
        select_all_action = QAction("全選", self)
        select_all_action.setShortcut("Ctrl+A")
        self.tableWidget.horizontalHeader().setContextMenuPolicy(Qt.ContextMenuPolicy.ActionsContextMenu)
        self.tableWidget.horizontalHeader().addAction(select_all_action)
        select_all_action.triggered.connect(self.tableWidget.selectAll)
        
        #複製
        copy_action = QAction("复制", self)
        copy_action.setShortcut("Ctrl+C")
        self.tableWidget.setContextMenuPolicy(Qt.ContextMenuPolicy.ActionsContextMenu)
        self.tableWidget.addAction(copy_action)
        copy_action.triggered.connect(self.copy_to_clipboard)
    def copy_to_clipboard(self):
        selected = self.tableWidget.selectedRanges()
        if not selected:
            return
        s = ""
        for r in range(selected[0].topRow(), selected[0].bottomRow()+1):
            for c in range(selected[0].leftColumn(), selected[0].rightColumn()+1):
                try:
                    s += str(self.tableWidget.item(r,c).text()) + "\t"
                except AttributeError:
                    s += "\t"
            s = s[:-1] + "\n" # eliminating last \t
        clipboard = QApplication.clipboard()
        clipboard.setText(s)
        print("以複製")
    def initConfig(self):
        self.lineEdit.setText(config["ECCS"]["idNo"])
        self.lineEdit_2.setText(config["ECCS"]["userId"])
        self.lineEdit_3.setText(config["ECCS"]["userPwd"])
    def writeiniInfo(self,idNo,userId,userPwd):
        config["ECCS"]["idNo"] = str(idNo)
        config["ECCS"]["userId"] = str(userId)
        config["ECCS"]["userPwd"] = str(userPwd)
        with open('config.ini', 'w') as configfile:    # save
            config.write(configfile)

    def search(self):
        idNo = self.lineEdit.text()
        userId = self.lineEdit_2.text()
        userPwd = self.lineEdit_3.text()
        self.lang = config["ECCS"]["lang"]
        self.userType = config["ECCS"]["userType"]
        self.writeiniInfo(idNo,userId,userPwd) #寫入帳號密碼

        textEditList = self.plainTextEdit.toPlainText().split("\n")

        
        try:
            eccs = Eccs(idNo,userId,userPwd,self.lang,self.userType)
            self.pushButton.setEnabled(False)
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(eccs.runEccsCheckPreverify(textEditList))
            self.pushButton.setEnabled(True)
            #預先委任
            self.tableWidget.setRowCount(len(result))
            for i,row in enumerate(result):
                for k,col in enumerate(row):
                    #print(i,k)
                    item = QTableWidgetItem(str(col))
                    self.tableWidget.setItem(i,k,item)

            # if self.radioButton_2.isChecked(): #電話
            #     result = eccs.EccsCheckPhone(textEditList)
            #     self.tableWidget.setRowCount(len(result))
            #     for i,row in enumerate(result):
            #         for k,col in enumerate(row):
            #             #print(i,k)
            #             item = QTableWidgetItem(str(col))
            #             self.tableWidget.setItem(i,k,item)
            # elif self.radioButton.isChecked():#身分證
            #     result = eccs.EccsCheckID(textEditList)
            #     self.tableWidget.setRowCount(len(result))
            #     for i,row in enumerate(result):
            #         for k,col in enumerate(row):
            #             #print(i,k)
            #             item = QTableWidgetItem(str(col))
            #             self.tableWidget.setItem(i,k,item)
        except Exception as e:
            print(e)
            return


if __name__ == '__main__':
    import sys
    app = QtWidgets.QApplication(sys.argv)
    loginWindow = LoginWindow()
   # window = MyWindow()
    
    loginWindow.show()
    sys.exit(app.exec())