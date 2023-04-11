# Sonarqube PDF Report Generation

## To Setup sonarqube on local system

### Requirements
```
docker
docker-compose
```

### Install docker and docker-compose
```
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
```
```
sudo apt-key fingerprint 0EBFCD88
```
```
sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"
```
```
sudo apt-get update
```
```
sudo apt-get install docker-ce docker-ce-cli containerd.io
```



### Start Sonarqube
```
cd sonarqube/
sudo docker-compose up -d 
```




# To Setup Report Generation Code

### Requirements
```
1. python 2.7
2. pip
3. wkhtmltopdf
```

Install dependencies using
```
pip2 install -r requirements.txt
pip2 install pdfkit
```

Install wkhtmltopdf ( This is a utility used to convert html to pdf )
```
sudo apt-get install wkhtmltopdf
```

To Generate Report
```
python generator.py <sonarqube url> <sonarqube port> <username> <password> <project name>
```
```
#Example command to generate report of project "oodles" from sonarqube running on local.
python generator.py localhost 9000 admin admin oodles
```
 
This will create a report of your project in the pdf_reports/ directory.

### NOTE: Please perform two project scanning action before creating PDF report as the pdf script check current result and last scan result to create final report
