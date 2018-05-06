#include "dialog.h"
#include "ui_dialog.h"
#include<iostream>

Dialog::Dialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog)
{
    ui->setupUi(this);
}

Dialog::~Dialog()
{
    delete ui;
}


void Dialog::on_pushButton_2_clicked()
{
    char * ch;
    QByteArray ba = ui->lineEdit->text().toLatin1();
    ch=ba.data();
    int i=0;
    for (i=0;ch[i]!='\0';i++)
    {
        //std::cout<<i<<std::endl;
        this->src_ip_str[i]=ch[i];
    }
    this->src_ip_str[i]='\0';
    //std::cout<<this->src_ip_str;
    ba = ui->lineEdit_2->text().toLatin1();
    ch=ba.data();
    for (i=0;ch[i]!='\0';i++)
    {
        //std::cout<<i<<std::endl;
        this->dst_ip_str[i]=ch[i];
    }
    this->dst_ip_str[i]='\0';

    bool ok;
    int jj;
    jj=ui->lineEdit_3->text().toInt(&ok,16);
    unsigned char *p=(unsigned char *)&jj;
    src_mac[0]=(u_int8_t)p[0];
    jj=ui->lineEdit_4->text().toInt(&ok,16);
     p=(unsigned char *)&jj;
    src_mac[1]=(u_int8_t)p[0];
    jj=ui->lineEdit_5->text().toInt(&ok,16);
     p=(unsigned char *)&jj;
    src_mac[2]=(u_int8_t)p[0];
    jj=ui->lineEdit_6->text().toInt(&ok,16);
     p=(unsigned char *)&jj;
    src_mac[3]=(u_int8_t)p[0];
    jj=ui->lineEdit_7->text().toInt(&ok,16);
     p=(unsigned char *)&jj;
    src_mac[4]=(u_int8_t)p[0];
    jj=ui->lineEdit_8->text().toInt(&ok,16);
     p=(unsigned char *)&jj;
    src_mac[5]=(u_int8_t)p[0];
    this->data=1;//arp 1
    this->close();
}

void Dialog::on_pushButton_clicked()
{
    char * ch;
    QByteArray ba = ui->lineEdit_9->text().toLatin1();
    ch=ba.data();
    int i=0;
    for (i=0;ch[i]!='\0';i++)
    {
        //std::cout<<i<<std::endl;
        this->src_ip_str[i]=ch[i];
    }
    this->src_ip_str[i]='\0';
    ba = ui->lineEdit_10->text().toLatin1();
    ch=ba.data();
    for (i=0;ch[i]!='\0';i++)
    {
        //std::cout<<i<<std::endl;
        this->dst_ip_str[i]=ch[i];
    }
    this->dst_ip_str[i]='\0';

    bool ok;
    int jj;
    jj=ui->lineEdit_11->text().toInt(&ok,16);
    unsigned char *p=(unsigned char *)&jj;
    src_mac[0]=(u_int8_t)p[0];
    jj=ui->lineEdit_12->text().toInt(&ok,16);
     p=(unsigned char *)&jj;
    src_mac[1]=(u_int8_t)p[0];
    jj=ui->lineEdit_13->text().toInt(&ok,16);
     p=(unsigned char *)&jj;
    src_mac[2]=(u_int8_t)p[0];
    jj=ui->lineEdit_14->text().toInt(&ok,16);
     p=(unsigned char *)&jj;
    src_mac[3]=(u_int8_t)p[0];
    jj=ui->lineEdit_15->text().toInt(&ok,16);
     p=(unsigned char *)&jj;
    src_mac[4]=(u_int8_t)p[0];
    jj=ui->lineEdit_16->text().toInt(&ok,16);
     p=(unsigned char *)&jj;
    src_mac[5]=(u_int8_t)p[0];
    this->data=2;//tcp 2

     this->src_port=(uint16_t)ui->lineEdit_17->text().toInt(&ok,10);
     this->des_port=(uint16_t)ui->lineEdit_18->text().toInt(&ok,10);
    this->serial_num=(uint32_t)ui->lineEdit_19->text().toInt(&ok,10);
    this->con_num=(uint32_t)ui->lineEdit_20->text().toInt(&ok,10);

}
