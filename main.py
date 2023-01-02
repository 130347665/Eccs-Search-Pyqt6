from PyQt6 import QtWidgets
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from Ui_gui import Ui_MainWindow
import requests
import asyncio
import aiohttp
import string
import json
import hashlib
import random
import time
import configparser

#機器瑪
import uuid
class register():
    def gen_machineCode(self):
        machine_code = uuid.getnode()
        machine_code_hash = hashlib.sha256(str(machine_code).encode('utf-8')).hexdigest()
        return machine_code_hash
    def checkregister(self):
        machineCode = self.gen_machineCode()
        httpregister = requests.get("https://raw.githubusercontent.com/130347665/Eccs-Search-Pyqt6/master/reistercode.txt").text.split("\n")
        print(machineCode)
        print(httpregister)
        try:
            httpregister.index(machineCode)
        except ValueError as e:
            print("未註冊")
        
    

 
checked = register().checkregister()
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
            if self.radioButton_2.isChecked(): #電話
                result = eccs.EccsCheckPhone(textEditList)
                self.tableWidget.setRowCount(len(result))
                for i,row in enumerate(result):
                    for k,col in enumerate(row):
                        #print(i,k)
                        item = QTableWidgetItem(str(col))
                        self.tableWidget.setItem(i,k,item)
            elif self.radioButton.isChecked():#身分證
                result = eccs.EccsCheckID(textEditList)
                self.tableWidget.setRowCount(len(result))
                for i,row in enumerate(result):
                    for k,col in enumerate(row):
                        #print(i,k)
                        item = QTableWidgetItem(str(col))
                        self.tableWidget.setItem(i,k,item)
        except Exception as e:
            return


if __name__ == '__main__':
    import sys
    app = QtWidgets.QApplication(sys.argv)
    window = MyWindow()
    
    window.show()
    sys.exit(app.exec())