import matplotlib.pyplot as plt
import numpy as np

AttackMethodAndAccuracy = {
    "Slow Post" : 0.96,
    "slowloris" : 0.99,
}

AttackMethodsKeys = list(AttackMethodAndAccuracy.keys())
Accuracy = list(AttackMethodAndAccuracy.values())

plt.bar(AttackMethodsKeys, Accuracy, color='blue',width=0.3)


plt.xlabel('Attack Methods')
plt.ylabel('Accuracy')
plt.title('CNN Model Accuracy on slowloris and Slow Post Attacks')
plt.ylim(0.9, 1.0)  # Limiting y-axis from 0.9 to 1.0

#plt.grid(True)
plt.tight_layout() 
plt.show()