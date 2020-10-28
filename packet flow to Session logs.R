# Title     : TODO
# Objective : TODO
# Created by: junimsarang
# Created on: 2020-10-27

install.packages("dplyr")
#install.packages("tidyverse")
library("dplyr")
#library("tidyverse")

#setwd("F:\PycharmProjects\SSH Detection using ML\Source Code")
temp <- read.csv(file = "meta.csv")
meta <- temp
meta <- na.omit(meta) ## no IP comm. exception
rownames(meta) <- NULL ## empty row arrange
# 프로토콜이 ssh와 http 인것만 추리자
# 먼저 로우 DNS를 뒤져서 no url 여부 확인
# SYN 열의 목적지 주소가 info에 포함되어 있는지?
meta$src_ip_port <- paste0(meta$Source,":",meta$Source.Port)
meta$dst_ip_port <- paste0(meta$Destination,":",meta$Destination.Port)
meta$send_byte <- 0
meta$receive_byte <- 0
meta$duration <- 0
meta$no_url <- 1
meta$start <- ifelse(grepl("SYN[]]", meta$Info),1,0)


## no_url 여부 확인해서 start packet에 업데이트, send, receive byte summation
i=1
for (i in 1:nrow(meta)) {
  if (meta$start[i] == 1) {

    l=1
    for (l in 1:i) {
      if (meta$Source.Port[l] == 53) {
        meta$no_url[i] <- ifelse(grepl(meta$Destination[i], meta$Info[l]), 0, 1)
        if (meta$no_url[l] == 0) {break}
      }
      else{}
      l=l+1
    }

    j <- i
    #meta$send_byte[i] = meta$Length[i]
    for (j in i:nrow(meta))  {
      if (meta$src_ip_port[j] == meta$src_ip_port[i]) {
        if (stop_bit == 1) {
          meta$send_byte[i] <- meta$send_byte[i] + meta$Length[j]
          break
        }
        meta$send_byte[i] <- meta$send_byte[i] + meta$Length[j]
        stop_bit <- ifelse(grepl("FIN", meta$Info[j]), 1, 0)
        }
      else if (meta$dst_ip_port[j] == meta$src_ip_port[i]) {
        if (stop_bit == 1) {
          meta$receive_byte[i] <- meta$receive_byte[i] + meta$Length[j]
          break
        }
        meta$receive_byte[i] <- meta$receive_byte[i] + meta$Length[j]
        stop_bit <- ifelse(grepl("FIN", meta$Info[j]), 1, 0)
      }
      else {}
      j=j+1
    }
    stop_bit = 0
    meta$duration[i] <- meta$Time[j-1] - meta$Time[i]
  }
  else {}
  i=i+1
}
