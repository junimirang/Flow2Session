import pandas as pd
import numpy as np


def data_read(file_name):
    # Original Column information : "No.","Time","Source","Destination","Protocol","Length","Source Port","Destination Port","Info"
    df = pd.read_csv(file_name)
    #IP 정보가 없는 행 삭제 : https://rfriend.tistory.com/263
    #print(df)
    #df = df.drop("No.")
    df = df.dropna(axis=0) ## 결측행 삭제
    df = df.reset_index() ## 행번호 추
    del df["index"], df["No."]
    time = df[["Time"]]
    src_ip = df[["Source"]]
    dst_ip = df[["Destination"]]
    protocol = df[["Protocol"]]
    length = df[["Length"]]
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
    df["NO URL"] = 1
    no_url = df[["NO URL"]]
    df["Send Byte"] = 0
    send_byte = df[["Send Byte"]]
    df["Receive Byte"] = 0
    receive_byte = df[["Receive Byte"]]
    #total_length = 15000
    total_length = len(info)
    n=0
    while n < total_length:
        if n%1000 == 0:
            print("This Counts:", n)
        if "[SYN]" in info["Info"][n]:
            start_pkt["Start Packet"][n] = 1
            stop_bit = 0
            #if n < 5000:
            if n >0:
                for i in range(n,0,-1):
                    if (dst_ip["Destination"][n] in info["Info"][i]) and ("Standard query response" in info["Info"][i]):
                        no_url["NO URL"][n] = 0
                        m=n-i
                        if m>5000:
                            print(m)
                        break
            #elif n >=5000:
            #    for i in range(n-3000,n):
            #        if (dst_ip["Destination"][n] in info["Info"][i]) and ("Standard query response" in info["Info"][i]):
            #            no_url["NO URL"][n] = 0
            for i in range(n,total_length):
                if (dst_ip_port["Destination_ip_port"][n] == dst_ip_port["Destination_ip_port"][i] and stop_bit == 0):
                    send_byte["Send Byte"][n] = send_byte["Send Byte"][n] + length["Length"][i]
                    if "FIN" in info["Info"][i]:
                        stop_bit = 1
                elif (dst_ip_port["Destination_ip_port"][n] == dst_ip_port["Destination_ip_port"][i] and stop_bit == 1):
                    send_byte["Send Byte"][n] = send_byte["Send Byte"][n] + length["Length"][i]
                    break
                elif (dst_ip_port["Destination_ip_port"][n] == src_ip_port["Source_ip_port"][i] and stop_bit == 0):
                    receive_byte["Receive Byte"][n] = receive_byte["Receive Byte"][n] + length["Length"][i]
                    if "FIN" in info["Info"][i]:
                        stop_bit = 1
                elif (dst_ip_port["Destination_ip_port"][n] == src_ip_port["Source_ip_port"][i] and stop_bit == 1):
                    receive_byte["Receive Byte"][n] = receive_byte["Receive Byte"][n] + length["Length"][i]
                    break
        n = n+1
    df["NO URL"] = no_url
    df["Start Packet"] = 0
    df["Start Packet"] = start_pkt
    df["Send Byte"] = send_byte
    df["Receive Byte"] = receive_byte
    return df

if __name__ == '__main__':
    file_name = "meta.csv"
    df = data_read(file_name)
    df.to_csv("temp.csv")