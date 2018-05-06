#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "packet.hpp"
#include<stdio.h>
//#include<string>
#include<itos.h>
#include<iostream>
Packet packet;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);//ui initial
    typedef enum
    {
        PROXY_NONE,      //没有代理
        PROXY_BROWSER,   //浏览器代理
        PROXY_HTTP,      //HTTP代理
        PROXY_SOCKS4,    //SOCK4代理
        PROXY_SOCK5,     //SOCK5代理
    }Proxy_Types;


    pcap_if_t *d;

    packet.findalldevs();
    int i=0;
    //string aa;

    for(d = packet.r; d; d = d->next)
    {   i=i+1;
       itos a;
       a.itos_t(i);
        //aa=String.valueOf(i);
       //QString qstr1="ert";
       //QString * q;
       //q=&qstr1;



        //qstr = QString::fromStdString(;
        ui->textBrowser->append(a.s);
        ui->textBrowser->append(d->name);
        ui->comboBox->addItem(d->name, PROXY_NONE);

       // ui->comboBox->addItem();
        if(d->description){
            //ui->textBrowser->append();
            ui->textBrowser->append(d->description);
        }
        else{
            ui->textBrowser->append("No description available");
        }
    }
    //packet.choosedev();




}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_clicked()
{

QString  str1;
QString str2;
bool ok;

char* ch;
char filter[30];
str1=ui->lineEdit->text();//filter
str2=ui->lineEdit_2->text();//num

QByteArray ba = str1.toLatin1();
int num=str2.toInt(&ok,10);

ch=ba.data();
int i;
for (i=0;i<30;i++)
{
    filter[i]=*(ch+i);
    //printf("%c\n",filter[i]);
}
packet.filter(filter);
//Packet_hand ss;
Packet w;
Packet j;
w.c=new u_char[89];
j=packet.capturePacket(num, filter,w);
string s9=(char *)&w.c[28];
ui->textBrowser->append(QString::fromStdString(s9));
if (w.c[28]=='2'&&w.c[29]=='0'&&w.c[30]=='5'&&w.c[31]=='4')
{
    ui->textBrowser->append("------------ ARP -------------");
    if(w.c[33]=='1')
        ui->textBrowser->append("Hardware type:Ethernet");
    else
        ui->textBrowser->append("Hardware type:Unknown");
    if(w.c[34]=='2'&&w.c[34]=='0'&&w.c[34]=='4'&&w.c[34]=='8')
        ui->textBrowser->append("Protocol type:IPv4");
    else
        ui->textBrowser->append("Protocol type:Unknown");
    if(w.c[39]=='1')
        ui->textBrowser->append("Operation :ARP_REQUEST");
    else
        ui->textBrowser->append("Operation :ARP_REPLY");
    string s1="Soucre MAC :";
    char s2[10];
    sprintf(s2,"%2x:",w.c[41]);
    string s3=s2;
    sprintf(s2,"%2x:",w.c[42]);
    string s4=s2;
    sprintf(s2,"%2x:",w.c[43]);
    string s5=s2;
    sprintf(s2,"%2x:",w.c[44]);
    string s6=s2;
    sprintf(s2,"%2x:",w.c[45]);
    string s7=s2;
    sprintf(s2,"%2x",w.c[46]);
    string s8=s2;
    s1=s1+s3+s4+s5+s6+s7+s8;


    ui->textBrowser->append(QString::fromStdString(s1));
    s1="Soucre IP :";
    sprintf(s2,"%d.",w.c[48]);
    s3=s2;
    sprintf(s2,"%d.",w.c[49]);
    s4=s2;
    sprintf(s2,"%d.",w.c[50]);
    s5=s2;
    sprintf(s2,"%d",w.c[51]);
    s6=s2;
    s1=s1+s3+s4+s5+s6;
    ui->textBrowser->append(QString::fromStdString(s1));

        s1="Destination MAC :";

        sprintf(s2,"%02x:",w.c[53]);
        s3=s2;
        sprintf(s2,"%02x:",w.c[54]);
        s4=s2;
        sprintf(s2,"%02x:",w.c[55]);
        s5=s2;
        sprintf(s2,"%02x:",w.c[56]);
        s6=s2;
        sprintf(s2,"%02x:",w.c[57]);
        s7=s2;
        sprintf(s2,"%02x",w.c[58]);
        s8=s2;
        s1=s1+s3+s4+s5+s6+s7+s8;
        ui->textBrowser->append(QString::fromStdString(s1));
        s1="Destination IP :";
        sprintf(s2,"%d.",w.c[60]);
        s3=s2;
        sprintf(s2,"%d.",w.c[61]);
        s4=s2;
        sprintf(s2,"%d.",w.c[62]);
        s5=s2;
        sprintf(s2,"%d",w.c[63]);
        s6=s2;
        s1=s1+s3+s4+s5+s6;
        ui->textBrowser->append(QString::fromStdString(s1));


}
//printf("time:%s\n",w.c);
//int j;

//for (j=0;j<15;j++)
//{
   // printf("%c",*packet.c);
//}
//ui->textBrowser->append();



}

void MainWindow::on_pushButton_2_clicked()
{
    bool ok;
    int num;
    QString str2;
    //printf("3333");
    str2=ui->lineEdit_3->text();

    num=ui->comboBox->currentIndex()+1;
    packet.choosedev(num);
}





void MainWindow::on_pushButton_4_clicked()
{
    //printf("333\n");
    QString  str;
    str=ui->lineEdit_3->text();


    QByteArray ba = str.toLatin1();


    //printf("2222\n");
    packet.send_single(&dialg1);
}

void MainWindow::on_actionsend_packet_triggered()
{
    this->hide();
    dialg1.show();
    dialg1.exec();
    this->show();
    //ui->textBrowser->append(dialg1.data);
   // std::cout<<dialg1.src_ip_str<<std::endl;
    //std::cout<<dialg1.dst_ip_str<<std::endl;

    //std::cout<<dialg1.src_mac[0]<<std::endl;
    //std::cout<<dialg1.src_mac[1]<<std::endl;
    //std::cout<<dialg1.src_mac[2]<<std::endl;
    //std::cout<<dialg1.src_mac[3]<<std::endl;
    //std::cout<<dialg1.src_mac[4]<<std::endl;
    //std::cout<<dialg1.src_mac[5]<<std::endl;
   if(dialg1.data==1)
    packet.send_single(&dialg1);
   else if(dialg1.data==2)
       packet.send_single_tcp(&dialg1);
   else
       printf("error");

}

void MainWindow::on_actionsend_tcp_triggered()
{

}
