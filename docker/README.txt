构建镜像：

docker build -t oldsystem .

运行容器：

docker run -d -p 28080:8080 --restart unless-stopped oldsystem
