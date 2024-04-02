import matplotlib.pyplot as plt

# 設定X軸的時間範圍(0~100秒)
x = list(range(100))

# 圖1: 流量固定(Y軸1-100)
plt.figure(1)
y1 = [50] * 100
plt.plot(x, y1)
plt.title('City Traffic - Scenario 1')
plt.xlabel('Time')
plt.ylabel('Traffic Flow')
plt.ylim(1, 100)  # 設定Y軸範圍

# 圖2: 三個區段的流量(Y軸1-100)
plt.figure(2)
# 定義X軸區段的範圍
Sx1 = x[:33]
Sx2 = x[33:66]
Sx3 = x[66:]
# 定義對應X範圍的Y值
Sy1 = [50] * len(Sx1)
Sy2 = [50] * len(Sx2)
Sy3 = [50] * len(Sx3)
# 繪製圖形
plt.plot(Sx1, Sy1, color='blue', label='Blue Section')
plt.plot(Sx2, Sy2, color='green', label='Green Section')
plt.plot(Sx3, Sy3, color='red', label='Red Section')
plt.title('City Traffic - Scenario 2')
plt.xlabel('Time')
plt.ylabel('Traffic Flow')
plt.ylim(1, 100)  # 設定Y軸範圍
plt.legend()

# 圖3: 流量高低起伏 (Y軸1-100)
plt.figure(3)
y3 = [0] + [0]*12 + [0 , 20 , 30 , 40 , 50 , 40 , 30 , 20 , 0] + [0]*12 + [0]*12 + [0 , 20 , 30 , 40 , 50 , 40 , 30 , 20 , 0] + [0]*12 + [0]*12 + [0 , 20 , 30 , 40 , 50 , 40 , 30 , 20 , 0] + [0]*12
plt.plot(x[:100], y3)
plt.title('City Traffic - Scenario 3')
plt.xlabel('Time')
plt.ylabel('Traffic Flow')
plt.ylim(1, 100)  # 設定Y軸範圍

# 圖4: 流量從小慢慢加大 (Y軸1-100)
plt.figure(4)
y4 = [12.5]*15 + [13]*25 + [20]*10 + [30]*10 + [35]*10 + [40]*10 + [50]*20
plt.plot(x, y4)
plt.title('City Traffic - Scenario 4')
plt.xlabel('Time')
plt.ylabel('Traffic Flow')
plt.ylim(1, 100)  # 設定Y軸範圍

# 顯示所有圖表
plt.show()
