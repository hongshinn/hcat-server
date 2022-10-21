# HCat-Server

## 简介

HCat-Server是HCat聊天室的服务端.

## 功能

- 好友系统
- 群租系统
- 自定义插件

## 使用方式

如果你是windows用户,你可以选择从Releases获取或者使用源码运行
如果你是linux用户,那很抱歉..你只能使用源码运行,但我相信,这难不倒你

1. 方式1:从Releases获取:
    1. 由[此处](https://github.com/hongshinn/hcat-server/releases/latest)下载HCat-Server的编译版本
    2. 运行其中的可执行文件
2. 方式2:使用源码运行:
    1. 你可以使用
        ```shell
        git clone https://github.com/hongshinn/hcat-server.git
        ```
       或着
       由[此处](https://github.com/hongshinn/hcat-server/releases/latest)下载HCat-Server的源码
    2. 进入HCat-Server的目录
    3. 运行HCat-Server
       ```shell
       pip3 install -r requirements.txt
       python3 main.py
       ```