# HW1-3th Edu | airodump

| Airodump!!!!!

---
## Execute
```
syntax : sudo ./airodump <interface> 
sample : sudo ./airodump wlan0

```
---
## ETC
_**추후 수정 내용**_<br>
### ENC 구현

- airodump-ng에서 802.11-sample1.pcap에 있는 U+NetA11D 패킷을 못잡음
- ENC에서 모든 WPA를 잡을 수 있었지만 airodump-ng에서도 잡을 수 없던 "U+NetA11D" 패킷으로 인해 segmentation fault 발생
- TRY CATCH도 먹지 않아 우선 주석처리

### PWR 구현
- RADIO Struct를 동적으로 만들다보니 Flag를 Check하는 부분을 추가하고 Offset을 계산해야하지만 시간 부족으로 추후 수정 예정

---
| BoB11 Hyeon Seak hun

| Reference : gilgil
