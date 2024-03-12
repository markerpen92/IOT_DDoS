import torch
import torch.nn as nn
import torch.optim as optim

class MyNetwork(nn.Module):
    def __init__(self):
        super(MyNetwork, self).__init__()
        self.layer1 = nn.Linear(3, 128)
        self.layer2 = nn.Linear(128, 128)
        self.layer3 = nn.Linear(128, 128)
        self.layer4 = nn.Linear(128, 128)
        self.output_layer = nn.Linear(128, 2)

    def forward(self, x):
        x = torch.relu(self.layer1(x))
        x = torch.relu(self.layer2(x))
        x = torch.relu(self.layer3(x))
        x = torch.relu(self.layer4(x))
        x = self.output_layer(x)
        return x

model = MyNetwork()

loaded_model = MyNetwork()

loaded_model.load_state_dict(torch.load('my_model.pth'))
loaded_model.eval()

test_input = ''

with torch.no_grad():
    predicted_labels = loaded_model(test_input)

print("Predicted Labels:")
print(predicted_labels)
