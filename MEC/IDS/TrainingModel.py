import torch
import torch.nn as nn
import torch.optim as optim

class MyNetwork(nn.Module):
    def __init__(self):
        super(MyNetwork , self).__init__()
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

print(model)


criterion = nn.CrossEntropyLoss()
optimizer = optim.SGD(model.parameters(), lr=0.01)

input_data = ''
target_data = ''


for epoch , training_data in enumerate(zip(input_data , target_data)) : 
    output = model(training_data[0])

    loss = criterion(output, target_data)

    optimizer.zero_grad()
    loss.backward()
    optimizer.step()

    if (epoch + 1) % 100 == 0:
        print(f'Epoch [{epoch+1}/{len(input_data)}], Loss: {loss.item():.4f}')


# new_data = ''
# predicted_labels = model(new_data)


torch.save(model.state_dict(), 'my_model.pth')

model = MyNetwork()
model.load_state_dict(torch.load('my_model.pth'))
model.eval()
