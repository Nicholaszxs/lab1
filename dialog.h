#ifndef DIALOG_H
#define DIALOG_H

#include <QDialog>
#include<libnet.h>

namespace Ui {
class Dialog;
}

class Dialog : public QDialog
{
    Q_OBJECT

public:
    explicit Dialog(QWidget *parent = 0);
    ~Dialog();

public:
    Ui::Dialog *ui;
    QString data;
    char *src_ip_str=new char[30];
    char *dst_ip_str=new char[30];
    u_int8_t src_mac[6];
    uint16_t src_port;
    uint16_t des_port;
    uint32_t serial_num;
    uint32_t con_num;
private slots:
    void on_buttonBox_accepted();
    void on_pushButton_2_clicked();
    void on_pushButton_clicked();
};

#endif // DIALOG_H
