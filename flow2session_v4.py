import pandas as pd
import math
import datetime

now = datetime.datetime.now()
print("Start Time : ",now)

# import numpy as np


def data_read(file_name):
    # Original Column information : "No.","Time","Source","Destination","Protocol","Length","Source Port","Destination Port","Info"
    df = pd.read_csv(file_name)
    # IP 정보가 없는 행 삭제 : https://rfriend.tistory.com/263
    # print(df)
    # df = df.drop("No.")
    df = df.dropna(axis=0)  ## 결측행 삭제
    df = df.reset_index()  ## 행번호 추가
    del df["index"], df["No."]
    time = df[["Time"]]
    src_ip = df[["Source"]]
    dst_ip = df[["Destination"]]
    protocol = df[["Protocol"]]
    length = df[["Length"]]
    df["Source Port"] = df["Source Port"].astype('int')
    df["Destination Port"] = df["Destination Port"].astype('int')
    src_port = df[["Source Port"]]
    dst_port = df[["Destination Port"]]
    info = df[["Info"]]
    ## pandas 열 추가, 삭제
    ## https://m.blog.naver.com/PostView.nhn?blogId=rising_n_falling&logNo=221631637822&proxyReferer=https:%2F%2Fwww.google.com%2F
    # 문자열 합치기 https://rfriend.tistory.com/389
    ## https://www.delftstack.com/ko/howto/python-pandas/how-to-combine-two-columns-of-text-in-dataframe-in-pandas/#df.apply%25EB%25A9%2594%25EC%2586%258C%25EB%2593%259C
    df["Source_ip_port"] = df["Source"] + ":" + df["Source Port"].map(str)
    df["Destination_ip_port"] = df["Destination"] + ":" + df["Destination Port"].map(str)
    src_ip_port = df[["Source_ip_port"]]
    dst_ip_port = df[["Destination_ip_port"]]
    print(len(info))
    df["Start Packet"] = 0
    start_pkt = df[["Start Packet"]]
    df["no_url"] = 1
    no_url = df[["no_url"]]
    df["Send Byte"] = 0
    send_byte = df[["Send Byte"]]
    df["Receive Byte"] = 0
    receive_byte = df[["Receive Byte"]]
    df["Duration"] = 0.0
    duration = df[["Duration"]]
    #total_length = 3000
    total_length = len(info)

    idx_not_dns = df[df["Source Port"] != 53].index
    df_dns = df.drop(idx_not_dns)
    df_dns = df_dns.reset_index()  ## 행번호 추가
    del df_dns["index"]
    dns_length = len(df_dns)
    print("DNS Length : ",dns_length)


    n = 0
    while n < total_length:
        if n % 1000 == 0:
            print("This Counts:", n)
        # Initial Packet Setup
        if "[SYN]" in info["Info"][n]:
            start_pkt["Start Packet"][n] = 1
            stop_bit = 0
            # DNS Check
            for i in range(dns_length):
                if (src_ip["Source"][n] == df_dns["Destination"][i]) and (dst_ip["Destination"][n] in df_dns["Info"][i]):
                    no_url["no_url"][n] = 0
                    break

            # Session Reassembling
            j=0
            for i in range(n, total_length):
                if (dst_ip_port["Destination_ip_port"][n] == dst_ip_port["Destination_ip_port"][i] and stop_bit == 0):
                    send_byte["Send Byte"][n] = send_byte["Send Byte"][n] + length["Length"][i]
                    j = i
                    if "FIN" in info["Info"][i]:
                        stop_bit = 1
                elif (dst_ip_port["Destination_ip_port"][n] == dst_ip_port["Destination_ip_port"][i] and stop_bit == 1):
                    send_byte["Send Byte"][n] = send_byte["Send Byte"][n] + length["Length"][i]
                    j = i
                    break
                elif (dst_ip_port["Destination_ip_port"][n] == src_ip_port["Source_ip_port"][i] and stop_bit == 0):
                    receive_byte["Receive Byte"][n] = receive_byte["Receive Byte"][n] + length["Length"][i]
                    j = i
                    if "FIN" in info["Info"][i]:
                        stop_bit = 1
                elif (dst_ip_port["Destination_ip_port"][n] == src_ip_port["Source_ip_port"][i] and stop_bit == 1):
                    receive_byte["Receive Byte"][n] = receive_byte["Receive Byte"][n] + length["Length"][i]
                    j = i
                    break
                #if (i > 10000):
                    #print("Ooooops", i)
            duration["Duration"][n] = time["Time"][j] - time["Time"][n]
        #print(n)
        n = n + 1

    df["no_url"] = no_url
    df["Start Packet"] = start_pkt
    df["Send Byte"] = send_byte
    df["Receive Byte"] = receive_byte
    df["Duration"] = duration
    df["log_time_taken"] = 0.0
    df["log_cs_byte"] = 0.0
    df["log_ratio_trans_receive"] = 0.0
    df["log_count_connect_IP"] = 0.0
    df["log_count_total_connect"] = 0.0
    df["log_avg_count_connect"] = 0.0
    df["log_transmit_speed_BPS"] = 0.0

    # start_pkt 이 아닌 열 지우기
    idx_start_pkt = df[df["Start Packet"] == 0].index
    df = df.drop(idx_start_pkt)
    df = df.reset_index()  ## 행번호 추가
    del df["index"]
    df["ratio_trans_receive"] = df["Send Byte"] / df["Receive Byte"]
    df["LABEL"] = "UNKNOWN"
    dst_port = df[["Destination Port"]]
    df["count_total_connect"] = 0
    df["count_connect_IP"] = 0

    total_length = len(df["Info"])
    for i in range(total_length):
        if dst_port["Destination Port"][i] == 21:
            df["LABEL"][i] = "FTP"
        if dst_port["Destination Port"][i] == 22:
            df["LABEL"][i] = "SSH"
        if dst_port["Destination Port"][i] == 23:
            df["LABEL"][i] = "TELNET"
        if dst_port["Destination Port"][i] == 25:
            df["LABEL"][i] = "SMTP"
        if dst_port["Destination Port"][i] == 53:
            df["LABEL"][i] = "DNS"
        if dst_port["Destination Port"][i] == 80:
            df["LABEL"][i] = "HTTP"
        if dst_port["Destination Port"][i] == 123:
            df["LABEL"][i] = "NTP"
        if dst_port["Destination Port"][i] == 443:
            df["LABEL"][i] = "HTTPS"
        if dst_port["Destination Port"][i] == 3389:
            df["LABEL"][i] = "RDP"

        if i == 0:
            for j in range(total_length):
                if df["Destination"][j] == df["Destination"][i]:
                    df["count_total_connect"][i] = df["count_total_connect"][i] + 1
                if (df["Destination"][j] == df["Destination"][i]) and (df["Source"][j] != df["Source"][i]):
                    df["count_connect_IP"][i] = df["count_connect_IP"][i] + 1

        if i >= 1:
            for j in range(i-1, -1, -1):
                if df["Destination"][i] == df["Destination"][j]:
                    df["count_total_connect"][i] = df["count_total_connect"][j]
                    df["count_connect_IP"][i] = df["count_connect_IP"][j]

            if df["count_total_connect"][i] == 0:
                df["count_total_connect"][i] = 1
                df["count_connect_IP"][i] = 1
                for j in range(i+1, total_length):
                    if df["Destination"][j] == df["Destination"][i]:
                        df["count_total_connect"][i] = df["count_total_connect"][i] + 1
                    if df["Destination"][j] == df["Destination"][i] and df["Source"][j] != df["Source"][i]:
                        df["count_connect_IP"][i] = df["count_connect_IP"][i] + 1

    df["avg_count_connect"] = df["count_total_connect"] / df["count_connect_IP"]
    df["transmit_speed_BPS"] = df["Send Byte"] / df["Duration"]

    for i in range(total_length):
        k1 = df["Duration"][i]
        df["log_time_taken"][i] = round(math.log10(k1), 2)
        k2 = df["Send Byte"][i]
        df["log_cs_byte"][i] = round(math.log10(k2), 2)
        k3 = df["ratio_trans_receive"][i]
        df["log_ratio_trans_receive"][i] = round(math.log2(k3), 2)
        k4 = df["count_connect_IP"][i]
        df["log_count_connect_IP"][i] = round(math.log2(k4), 2)
        k5 = df["count_total_connect"][i]
        df["log_count_total_connect"][i] = round(math.log2(k5), 2)
        k6 = df["avg_count_connect"][i]
        df["log_avg_count_connect"][i] = round(math.log10(k6), 2)
        k7 = df["transmit_speed_BPS"][i]
        df["log_transmit_speed_BPS"][i] = round(math.log2(k7 + 1), 2)

    return df

if __name__ == '__main__':
    file_name = "meta.csv"
    df = data_read(file_name)
    df.to_csv("session_output.csv")
    print("End Time : ", now)
