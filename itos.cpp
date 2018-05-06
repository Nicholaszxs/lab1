#include<itos.h>
void itos::itos_t(int i){
    std::string str1;
    switch (i) {
    case 0:
        str1="0:";
        break;
    case 1:
        str1="1:";
        break;
    case 2:
        str1="2:";
        break;
    case 3:
        str1="3:";
        break;
    case 4:
        str1="4:";
        break;
    case 5:
        str1="5:";
        break;
    case 6:
        str1="6:";
        break;
    case 7:
        str1="7:";
        break;
    case 8:
        str1="8:";
        break;
    case 9:
        str1="9:";
        break;

    default:
        str1="erro";
        break;
    }
    this->s = QString::fromStdString(str1);
}
