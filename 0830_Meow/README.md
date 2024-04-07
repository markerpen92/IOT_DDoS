# Applying_Multi-Access_Edge_Computing_to_IoT_Malicious_Attack_Detection

python3.5 topov2.py 

# Image Setting
docker pull kathara/quagga


docker run --privileged -it kathara/quagga:latest bash
docker run --privileged -it kathara/quagga:v1.1 bash


# Update repository Source $ Install requre Software 
echo "deb http://archive.debian.org/debian stretch main" > /etc/apt/sources.list
apt update 

sudo apt-get install libnetfilter-queue-dev


# Install MiniCOnda
wget -c https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
chmod +x Miniconda3-latest-Linux-x86_64.sh
./Miniconda3-latest-Linux-x86_64.sh


//查看ENV
conda info --envs



pip install netfilterqueue
pip install scapy
pip install numpy