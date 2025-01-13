import sys

from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QTextEdit, QLabel
from WOX7002 import deviceMapping


class StringProcessorApp(QWidget):
    def __init__(self,device):
        super().__init__()
        self.initUI()
        self.flag=0
        self.device = device
    def initUI(self):
        # 主布局
        main_layout = QHBoxLayout()

        # 左侧按钮区域布局
        button_layout = QVBoxLayout()
        # 右侧输入和输出区域布局
        right_layout = QVBoxLayout()
        # 添加处理方法的按钮
        self.arp_button = QPushButton('ARP_Ping', self)
        self.arp_button.clicked.connect(self.arp_ping)
        button_layout.addWidget(self.arp_button)

        self.arp_button = QPushButton('ICMP_Ping', self)
        self.arp_button.clicked.connect(self.icmp_ping)
        button_layout.addWidget(self.arp_button)

        self.tcp_syn_button = QPushButton('TCP_SYN_PING', self)
        self.tcp_syn_button.clicked.connect(self.tcp_syn_ping)
        button_layout.addWidget(self.tcp_syn_button)

        self.tcp_ack_button = QPushButton('TCP_ACK_PING', self)
        self.tcp_ack_button.clicked.connect(self.tcp_ack_ping)
        button_layout.addWidget(self.tcp_ack_button)

        self.udp_button = QPushButton('udp_PING', self)
        self.udp_button.clicked.connect(self.udp_ping)
        button_layout.addWidget(self.udp_button)

        self.udp_button = QPushButton('clear_output', self)
        self.udp_button.clicked.connect(self.clear_output)
        button_layout.addWidget(self.udp_button)
        # 添加按钮布局到主布局
        main_layout.addLayout(button_layout)

        # 输入框
        self.input_field = QLineEdit(self)
        self.input_field.setPlaceholderText("input IP e.g. 10.10.10.10/16")
        right_layout.addWidget(self.input_field)

        # 输出框（QTextEdit 用于多行输出）
        self.output_area = QTextEdit(self)
        self.output_area.setReadOnly(True)  # 设置为只读
        right_layout.addWidget(self.output_area)

        # 将右侧布局添加到主布局
        main_layout.addLayout(right_layout)

        # 设置窗口的主布局
        self.setLayout(main_layout)
        self.setWindowTitle('WOX7002 assignment1,Dong Xinyu')

    def arp_ping(self):
        input_text = self.input_field.text()
        a.set_ipaddr(input_text)
        l = a.run_arp()

        for i in l:
            self.output_area.append(i)

    def icmp_ping(self):
        input_text = self.input_field.text()
        a.set_ipaddr(input_text)
        l = a.run_icmp()
        for i in l:
            self.output_area.append(i)
        self.output_area.append('Finished!\n')

    def tcp_syn_ping(self):
        input_text = self.input_field.text()
        a.set_ipaddr(input_text)
        l = a.run_tcp()
        for i in l:
            self.output_area.append(i)
        self.output_area.append('Finished!\n')

    def tcp_ack_ping(self):
        input_text = self.input_field.text()
        a.set_ipaddr(input_text)
        l = a.run_tcp(80,'A')
        for i in l:
            self.output_area.append(i)
        self.output_area.append('Finished!\n')

    def udp_ping(self):
        input_text = self.input_field.text()
        a.set_ipaddr(input_text)
        l = a.run_udp()
        for i in l:
            self.output_area.append(i)
        self.output_area.append('Finished!\n')

    def clear_output(self):
        # 清空输出区域
        self.output_area.clear()

if __name__ == '__main__':
    a = deviceMapping()
    app = QApplication(sys.argv)
    ex = StringProcessorApp(a)
    ex.show()
    sys.exit(app.exec_())