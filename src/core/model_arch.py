import torch
import torch.nn as nn

class HybridCNNBiLSTM(nn.Module):
    def __init__(self, feature_size=20, num_classes=2):
        super(HybridCNNBiLSTM, self).__init__()
        
        # 1. CNN Layer (Renamed to match your saved 'cnn.weight' and 'cnn.bias')
        # We use the raw layer instead of Sequential to avoid the '.0' index error
        self.cnn = nn.Conv1d(in_channels=feature_size, out_channels=64, kernel_size=3, padding=1)
        self.relu = nn.ReLU()
        self.bn = nn.BatchNorm1d(64) # Note: If your saved model didn't have BN, we might need to remove this
        
        # 2. BiLSTM Layer
        self.lstm = nn.LSTM(
            input_size=64, 
            hidden_size=128, 
            num_layers=2, 
            batch_first=True, 
            bidirectional=True,
            dropout=0.3
        )
        
        # 3. Fully Connected Layers (Renamed 'classifier' to 'fc' to match your saved file)
        # We define them individually to match the 'fc.0' and 'fc.3' keys in your error
        self.fc = nn.Sequential(
            nn.Linear(128 * 2, 64), 
            nn.ReLU(),
            nn.Dropout(0.5),
            nn.Linear(64, num_classes)
        )

    def forward(self, x):
        # x: (Batch, 10, 20)
        x = x.permute(0, 2, 1) # -> (Batch, 20, 10)
        
        x = self.cnn(x)
        x = self.relu(x)
        # If your saved model didn't have BatchNorm, comment the next line out:
        # x = self.bn(x) 
        
        x = x.permute(0, 2, 1) # -> (Batch, 10, 64)
        
        lstm_out, _ = self.lstm(x)
        last_time_step = lstm_out[:, -1, :]
        
        return self.fc(last_time_step)