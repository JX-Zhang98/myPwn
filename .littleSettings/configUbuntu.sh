# 换源
# 切中文
# upgrade **在软件更新中安装核心组件更新**
# 升级后可能无法进入桌面，在grub 页按e，在启动选项倒数第二项后加 splash nomodeset，按F10进入后进入
sudo apt-get autoremove open-vm-tools
sudo apt-get install open-vm-tools-desktop
# 基本环境
sudo apt-get install gcc g++ libncurses5-dev libgnome2-dev python-dev python3-dev build-essential cmake 
sudo apt-get install python-pip python3-pip vim ;# vim 直安支持py3，无需另编译安装
fix pip
# 
# pip 换源
'''
[global] 
index-url = http://mirrors.aliyun.com/pypi/simple/
[install] 
trusted-host=mirrors.aliyun.com
'''
sudo python3 fixpip.py; sudo python fixpip.py
sudo apt-get install bpython3 bpython

# 配置git
git config --global user.name "JX-Zhang98"
git config --global user.email "jx_zhang98@qq.com"
ssh-keygen -t rsa -C "jx_zhang98@qq.com"
# ssh -T git@github.com
cat .ssh/id_rsa.pub 

# 32位运行库
sudo dpkg --add-architecture i386
sudo apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386

# deepin-terminal
git clone https://github.com/linuxdeepin/deepin-terminal-old #based on GTK instead of DTK

sudo apt-get update
sudo apt-get install valac cmake g++ intltool libgtk-3-dev libgee-0.8-dev libjson-glib-dev libsecret-1-dev libwnck-3-dev librsvg2-dev libreadline-dev libpcre2-dev gobject-introspection libgirepository1.0-dev gperf libxml2-utils
sudo apt-get install libatk1.0-0 libc6 libcairo-gobject2 libcairo2 libfontconfig1 libgdk-pixbuf2.0-0 libgee-0.8-2 libglib2.0-0 libgnutls30 libgtk-3-0 libice6 libjson-glib-1.0-0 libpango-1.0-0 libpangocairo-1.0-0 libpcre2-8-0 libreadline7 librsvg2-2 libsecret-1-0 libsm6 libstdc++6 libtinfo5 libwnck-3-0 libx11-6 libxext6 zlib1g lrzsz expect deepin-menu
sudo cp -r deepin-terminal-old /usr/share/
cd deepin-terminal-old
sudo mkdir build; cd build; sudo cmake ..; sudo make;
# make install #cp binary to /usr/bin/ 

sudo add-apt-repository ppa:daniel-marynicz/filemanager-actions
sudo apt-get update
sudo apt-get install filemanager-actions-nautilus-extension
fma-config-tool
# ref:https://blog.csdn.net/bestBT/article/details/81221378
gsettings set org.gnome.desktop.default-applications.terminal exec /usr/bin/deepin-terminal
gsettings set org.gnome.desktop.default-applications.terminal exec-arg "-x"


# zsh
sudo apt install zsh
sh -c "$(wget https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh -O -)"
# 出现wget无法建立ssl链接的问题
wget https://codeload.github.com/powerline/fonts/zip/master
unzip master
cd fonts-master && ./install.sh
# 更换字体 Noto Mono for Powerline (agnoster)

# vscode 
# 保存vscode配置
# Setting Sync,使用github进行同步
# ref https://www.cnblogs.com/Sweepingmonk/p/10868786.html

# 美化
# ref：https://magiclen.org/macbuntu-18-04/
sudo add-apt-repository ppa:noobslab/macbuntu
sudo apt install gnome-tweak-tool gnome-shell-extensions  slingscold albert macbuntu-os-plank-theme-v1804 
# gnome-tweak-tool即gnome-tweaks; 扩充套件即扩展
https://www.youtube.com/watch?v=sT1MHarE9Wo
# 美化登录页面

# 美化开机页 # 虚拟机无用
# ref：https://blog.csdn.net/weixin_44145894/article/details/105130336

# tensorflow
# aliyun
# install in system
sudo pip3 install tensorflow==1.14


# ref: https://www.tensorflow.org/install/pip#tensorflow-2-packages-are-available
# install in vir env
virtualenv --system-site-packages -p python3 ./venv
source ./venv/bin/activate
pip install --upgrade tensorflow-cpu
···
deactive

# 配置vim

# angr
# ref:https://github.com/a7vinx/angr-doc-zh_CN/blob/master/INSTALL.md
sudo apt-get install python3-dev libffi-dev build-essential  -y
sudo pip3 install virtualenvwrapper # mkvirturalenv command not found now
echo "export VIRTUALENVWRAPPER_PYTHON=/usr/bin/python3 \ export WORKON_HOME=$HOME/.virtualenvs" > ~/.zshrc
echo "source $(whereis virturalenvwrapper.sh)" > ~/.zshrc
source ~/.zshrc
mkvirtualenv --python=$(which python3) angr #&& pip install angr 
# 后面进入虚拟环境使用workon命令
workon angr
# 退出环境：deactivate 
# 删除环境: rmvirtualenv
pip3 install angr==8.18.10.25 or any other version
# if install with sudo, angr is installed in system instead of virtual env
python3
    import angr
#git clone https://github.com/angr/angr-dev
#sudo ./setup.sh -i -p angr

#arm compiler
# extract zip  to /usr/share/arm/gcc-4.6.4
# add to .zshrc
export PATH=$PATH:/usr/share/arm/gcc-4.6.4/bin
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/share/arm/gcc-4.6.4/lib

# compile arm64 kernel
cp ./arch/arm64/configs/defconfig .config

# make ARCH=arm64 CROSS_COMPILE=/usr/local/toolchains/gcc-linaro-4.9.4-2017.01-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu- all
    #Error:/bin/sh: 1: flex: not found
    sudo apt-get install flex
    #ERror:/bin/sh: 1: bison: not found
    sudo apt-get install bison