#include "widget.h"
#include <condition_variable>
#include <QApplication>
#include <thread>
#include <queue>




int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    Widget w;
    w.show();
    return a.exec();


}
