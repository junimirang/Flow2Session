import pandas as pd
import math
import datetime
import sys
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
    # total_length = 3000
    total_length = len(info)

    idx_not_dns = df[df["Source Port"] != 53].index
    df_dns = df.drop(idx_not_dns)
    df_dns = df_dns.reset_index()  ## 행번호 추가
    del df_dns["index"]
    dns_length = len(df_dns)
    print("DNS Length : ", dns_length)

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
                if (src_ip["Source"][n] == df_dns["Destination"][i]) and (
                        dst_ip["Destination"][n] in df_dns["Info"][i]):
                    no_url["no_url"][n] = 0
                    break

            # Session Reassembling
            j = 0
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
                # if (i > 10000):
                # print("Ooooops", i)
            duration["Duration"][n] = time["Time"][j] - time["Time"][n]
        # print(n)
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
    df["Business.time"] = 0
    df["Business.time"] = df["Business.time"].astype(int)

    # start_pkt 이 아닌 열 지우기
    idx_start_pkt = df[df["Start Packet"] == 0].index
    df = df.drop(idx_start_pkt)
    idx_miss_receive = df[df["Receive Byte"] == 0.0].index
    df = df.drop(idx_miss_receive)
    df = df.reset_index()  ## 행번호 추가
    del df["index"]
    df["ratio_trans_receive"] = df["Send Byte"] / df["Receive Byte"]

    df["LABEL"] = "UNKNOWN"
    dst_port = df[["Destination Port"]]
    df["count_total_connect"] = 0
    df["count_connect_IP"] = 0

    idx_ftp = df[df["Destination Port"] == 21].index
    df["LABEL"][idx_ftp] = "ftp"
    idx_ssh = df[df["Destination Port"] == 22].index
    df["LABEL"][idx_ssh] = "ssh"
    idx_telnet = df[df["Destination Port"] == 23].index
    df["LABEL"][idx_telnet] = "telnet"
    idx_smtp = df[df["Destination Port"] == 25].index
    df["LABEL"][idx_smtp] = "smtp"
    idx_dns = df[df["Destination Port"] == 53].index
    df["LABEL"][idx_dns] = "dns"
    idx_HTTP = df[df["Destination Port"] == 80].index
    df["LABEL"][idx_HTTP] = "web"
    idx_ntp = df[df["Destination Port"] == 123].index
    df["LABEL"][idx_ntp] = "ntp"
    idx_https = df[df["Destination Port"] == 443].index
    df["LABEL"][idx_https] = "web"
    idx_rdp = df[df["Destination Port"] == 3389].index
    df["LABEL"][idx_rdp] = "rdp"

    df.to_csv("session_output_without_ip_count.csv")
    df = df.dropna(axis=0)  ## 결측행 삭제



    ### 목적지,출발지 접속 카운트 ###
    # https://nittaku.tistory.com/131
    # https://rfriend.tistory.com/456
    count_ip = df.groupby([df["Destination"], df["Source"]]).count()
    count_ip = count_ip.reset_index().rename(columns={"Time": "Count"})
    count_ip = count_ip[["Destination", "Source", "Count"]]

    count_total_connect = count_ip.groupby("Destination")["Count"].sum()
    count_total_connect = count_total_connect.reset_index().rename(columns={"index": "Destination"})
    count_connect_ip = count_ip.groupby("Destination")["Source"].count()
    count_connect_ip = count_connect_ip.reset_index().rename(columns={"Source": "Count"})

    total_length = len(df["Info"])
    count_connect_ip_length = len(count_connect_ip["Count"])
    #count_total_connect_length = len(count_total_connect["Count"])

    for i in range(total_length):
        for j in range(count_connect_ip_length):
            if count_connect_ip["Destination"][j] == df["Destination"][i]:
                df["count_connect_IP"][i] = count_connect_ip["Count"][j]
                df["count_total_connect"][i] = count_total_connect["Count"][j]
                break


    df["avg_count_connect"] = df["count_total_connect"] / df["count_connect_IP"]
    df["transmit_speed_BPS"] = df["Send Byte"] / df["Duration"]


    df = df.dropna(axis=0)  ## 결측행 삭제

    df.to_csv("session_output_without_log_calculation.csv")

    idx_miss = df[df["Duration"] == 0.0].index
    df = df.drop(idx_miss)
    df = df.reset_index()  ## 행번호 추가
    total_length = len(df["Info"])

    for i in range(total_length):
        k1 = df["Duration"][i]
        k2 = df["Send Byte"][i]
        k3 = df["ratio_trans_receive"][i]
        k4 = df["count_connect_IP"][i]
        k5 = df["count_total_connect"][i]
        k6 = df["avg_count_connect"][i]
        k7 = df["transmit_speed_BPS"][i]
        df["log_time_taken"][i] = round(math.log10(k1*1000), 2)  ## sec to msec
        df["log_cs_byte"][i] = round(math.log10(k2), 2)
        df["log_ratio_trans_receive"][i] = round(math.log2(k3), 2)
        df["log_count_connect_IP"][i] = round(math.log2(k4), 2)
        df["log_count_total_connect"][i] = round(math.log2(k5), 2)
        df["log_avg_count_connect"][i] = round(math.log10(k6), 2)
        df["log_transmit_speed_BPS"][i] = round(math.log2(k7 + 1), 2)
        if (df["Time"][i]  <= 11*3600):   ## 08:00 ~ 19:00
            df["Business.time"][i] = 1
    return df

def normalization():
    df["log_time_taken_norm"] = 100*(df["log_time_taken"]-min(df["log_time_taken"]))/(max(df["log_time_taken"])-min(df["log_time_taken"]))
    df["log_cs_byte_norm"] = 100*(df["log_cs_byte"] - min(df["log_cs_byte"])) / (max(df["log_cs_byte"]) - min(df["log_cs_byte"]))
    df["log_ratio_trans_receive_norm"] = 100*(df["log_ratio_trans_receive"] - min(df["log_ratio_trans_receive"])) / (max(df["log_ratio_trans_receive"]) - min(df["log_ratio_trans_receive"]))
    df["log_count_connect_IP_norm"] = 100*(df["log_count_connect_IP"] - min(df["log_count_connect_IP"]))/ (max(df["log_count_connect_IP"]) - min(df["log_count_connect_IP"]))
    df["log_count_total_connect_norm"] = 100*(df["log_count_total_connect"] - min(df["log_count_total_connect"]))/ (max(df["log_count_total_connect"]) - min(df["log_count_total_connect"]))
    df["log_avg_count_connect_norm"] = 100*(df["log_avg_count_connect"] - min(df["log_avg_count_connect"]))/ (max(df["log_avg_count_connect"]) - min(df["log_avg_count_connect"]))
    df["log_transmit_speed_BPS_norm"] = 100*(df["log_transmit_speed_BPS"] - min(df["log_transmit_speed_BPS"]))/ (max(df["log_transmit_speed_BPS"]) - min(df["log_transmit_speed_BPS"]))
    retrun df


if __name__ == '__main__':
    # sys.stdout = open('flow2session_output.csv', 'w')       # Print as file #
    now = datetime.datetime.now()
    print("Start Time : ", now)
    file_name = "mon.csv"
    df = data_read(file_name)
    df.to_csv("session_output_mon.csv")
    file_name = "tue.csv"
    df = data_read(file_name)
    df.to_csv("session_output_tue.csv")
    file_name = "wed.csv"
    df = data_read(file_name)
    df.to_csv("session_output_wed.csv")
    file_name = "thu.csv"
    df = data_read(file_name)
    df.to_csv("session_output_thu.csv")
    file_name = "fri.csv"
    df = data_read(file_name)
    df.to_csv("session_output_fri.csv")

    ## data concate
    df1 = pd.read_csv("session_output_mon.csv")
    df2 = pd.read_csv("session_output_tue.csv")
    df3 = pd.read_csv("session_output_wed.csv")
    df4 = pd.read_csv("session_output_thu.csv")
    df5 = pd.read_csv("session_output_fri.csv")
    df = pd.concat([df1,df2,df3,df4], ignore_index=True)
    df.to_csv("session_output_total.csv")
    df = normalization(df)
    
    print("End Time : ", now)
    # sys.stdout = sys.__stdout__  # End of stdout
