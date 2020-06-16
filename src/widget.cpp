#include "widget.h"
#include "cmake-build-debug/DES64EncDec_autogen/include/ui_widget.h"
#include "IntoBits.h"



static QString currentlySelPath = "";

enum class ActionToPerform {
    ENCRYPT,
    DECRYPT,
    UNSELECTED
};

static ActionToPerform currentSelection = ActionToPerform::UNSELECTED;

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
}

Widget::~Widget()
{
    delete ui;
}

/**
 * slot methods
 */
void Widget::setValue(int value){

    ui->progressBar->setValue(value);
}
void Widget::setProgressBarValues(int value){
    ui->progressBar->setRange(0, (value-1));
}
void Widget::setTextField(QString string){
    ui->textBrowser_2->append(string);
}


void Widget::on_pushButton_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this,
                                                    tr("Select File"),
                                                    "C://",
                                                    "All files (*.*)"
                                                    );
    ui->textBrowser->setText(fileName);
    currentlySelPath = fileName;
}

void Widget::on_radioButton_toggled(bool checked)
{
    checked?(currentSelection = ActionToPerform::ENCRYPT):(currentSelection = ActionToPerform::UNSELECTED);
}

void Widget::on_radioButton_2_toggled(bool checked)
{
    checked?(currentSelection = ActionToPerform::DECRYPT):(currentSelection = ActionToPerform::UNSELECTED);
}

void Widget::on_pushButton_2_clicked()
{
    QElapsedTimer timer;
    timer.start();
    ui->pushButton_2->setDisabled(true);
    ui->pushButton->setDisabled(true);

    auto encDec = new DES64Crypto();

    std::string keyString = (ui->lineEdit->text()).toStdString();
    ui->lineEdit->clear();

    QObject::connect(encDec, &DES64Crypto::valueChanged, this, &Widget::setValue);
    QObject::connect(encDec, &DES64Crypto::sizeOfBar, this, &Widget::setProgressBarValues);
    QObject::connect(encDec, &DES64Crypto::updateTextField, this, &Widget::setTextField);
    ui->textBrowser_2->clear();

    std::string filePath = currentlySelPath.toStdString();
    long long fSize = IntoBits::getFileSize(filePath);
    if (currentSelection == ActionToPerform::ENCRYPT && currentlySelPath != ""){

        if (!keyString.empty() && keyString.length() < 9){
            uint64_t key = IntoBits::turnStringKeyIntoUint64T(keyString);
            encDec->setCryptoKey(key);
            try {
                //if file larger than 32 mb, use buffers, else dont
                if ((fSize > 32000000)){
                    encDec->bufferedFileEncryptionECB(filePath, key);
                } else if (fSize <= 32000000 && fSize != -1){
                    encDec->encryptFileECB(filePath, key);
                } else {
                    throw WrongFileException();
                }
            } catch (WrongFileException &e) {
                ui->lineEdit->setText("This program can't deal with this file extension");
                ui->textBrowser->clear();
                ui->textBrowser_2->clear();
                ui->pushButton_2->setDisabled(false);
                ui->pushButton->setDisabled(false);
                return;
            }
            qDebug() << timer.elapsed();
            ui->lineEdit->clear();
            ui->textBrowser->clear();
            QMessageBox msgBox;
            msgBox.setText("File successfully encrypted");
            msgBox.exec();
            ui->progressBar->setValue(0);
        }else{
            ui->lineEdit->setText("Please enter a key here (no more than 8 characters)!");
        }

    }else if(currentSelection == ActionToPerform::DECRYPT && currentlySelPath != ""){
        if (!keyString.empty() && keyString.length() < 9){
            uint64_t key = IntoBits::turnStringKeyIntoUint64T(keyString);
            encDec->setCryptoKey(key);
            //if file larger than 32 mb, use buffers, else dont
            try {
                //if file larger than 32 mb, use buffers, else dont
                if ((fSize > 32000000)){
                    encDec->bufferedFileDecryptionECB(filePath, key);
                } else if (fSize <= 32000000 && fSize != -1){
                    encDec->decryptFileECB(filePath, key);
                } else {
                    throw WrongFileException();
                }
            } catch (WrongFileException &e) {
                ui->lineEdit->setText("This program can't deal with this file extension");
                ui->textBrowser->clear();
                ui->textBrowser_2->clear();
                ui->pushButton_2->setDisabled(false);
                ui->pushButton->setDisabled(false);
                return;
            }
            qDebug() << timer.elapsed();
            ui->lineEdit->clear();
            ui->textBrowser->clear();
            QMessageBox msgBox;
            msgBox.setText("File successfully decrypted");
            msgBox.exec();
            ui->progressBar->setValue(0);
        }else{
            ui->lineEdit->setText("Please enter a key here (no more than 8 characters)!");
        }
    }else{
        ui->lineEdit->setText("Please select encryption or decryption");

    }
    ui->pushButton_2->setDisabled(false);
    ui->pushButton->setDisabled(false);
    delete encDec;
}

