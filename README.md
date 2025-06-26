# 🛡️ PhishGuard Pro - AI Email Phishing Detector



An advanced AI-powered email phishing detection system that combines Natural Language Processing and Machine Learning to identify malicious emails with high accuracy.

## 📊 Performance Metrics

- **Accuracy**: 97.18%
- **Precision**: 97% (Ham), 97% (Spam)
- **Recall**: 97% (Ham), 97% (Spam)
- **F1-Score**: 97% (both classes)
- **Dataset Size**: 193,850 email samples

##  Features

- **Real-time Email Analysis**: Instant classification with confidence scoring
- **Intelligent Explanations**: Detailed reasoning for each prediction
- **Advanced NLP Processing**: TF-IDF vectorization with comprehensive text preprocessing
- **Phishing Indicators Detection**: 
  - Suspicious URL patterns
  - Urgent/threatening language
  - Personal information requests
  - Grammar and formatting anomalies
- **Premium GUI Interface**: User-friendly desktop application
- **Analysis History**: Track and review previous analyses
- **Sample Email Testing**: Built-in phishing and legitimate email samples

## 🏗️ Technical Architecture

### Machine Learning Pipeline
```
Raw Email Text → Preprocessing → TF-IDF Vectorization → Logistic Regression → Classification + Confidence
```

### Key Components
- **Preprocessing**: Tokenization, stopword removal, punctuation cleaning
- **Vectorization**: TF-IDF with max_features=5000
- **Model**: Optimized Logistic Regression (scikit-learn)
- **GUI**: Premium Tkinter interface with modern design

## 📋 Requirements

```bash
numpy>=1.21.0
pandas>=1.3.0
scikit-learn>=1.0.0
joblib>=1.1.0
tkinter (usually comes with Python)
```

## 🛠️ Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/phishguard-pro.git
cd phishguard-pro
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Download/Create Model Files
Since the model files are large, you'll need to either:

**Option A: Train Your Own Model**
```bash
python train_model.py
```

**Option B: Download Pre-trained Models**
- Download `phishing_model(1).pkl` and `vectorizer(1).pkl`
- Place them in the project root directory

### 4. Run the Application
```bash
python gui_updated.py
```

## 📖 Usage

### Desktop Application
1. Launch the GUI application
2. Enter email content in the text area or load from file
3. Click "🔍 ANALYZE EMAIL" to get results
4. View detailed analysis and confidence score
5. Check analysis history for previous results

### Sample Testing
- Use "⚠️ SAMPLE PHISHING" to test with a phishing example
- Use "✅ SAMPLE SAFE" to test with a legitimate email example

## 🔬 Model Performance

### Confusion Matrix
```
                Predicted
              Ham    Spam
Actual  Ham  19709   608
        Spam  487   17966
```

### Classification Metrics
| Class | Precision | Recall | F1-Score | Support |
|-------|-----------|--------|----------|---------|
| Ham   | 0.98      | 0.97   | 0.97     | 20,317  |
| Spam  | 0.97      | 0.97   | 0.97     | 18,453  |

## 🎯 Key Innovations

- **Interpretable AI**: Provides detailed explanations for each classification
- **Multi-layered Analysis**: Combines statistical ML with rule-based indicators
- **Real-time Processing**: Instant analysis with confidence scoring
- **User Education**: Explains why emails are classified as phishing



## 👥 Team

- **Bhargav Rav Dutta** - Software Coordinator
- **Taha Nagdawala** - Software Coordinator  
- **Saihan Shafique** - Project Activity Coordinator
- **Roudah Ashfaq** - Project Activity Coordinator

## 🔮 Future Enhancements

- [ ] Integration with transformer models (BERT/RoBERTa)
- [ ] Real-time email client integration
- [ ] Web-based interface
- [ ] API for enterprise integration
- [ ] Advanced URL analysis and link verification
- [ ] Multi-language support




## 📜 License

This project is licensed under the MIT License 

## 🙏 Acknowledgments

- Dataset sources and research papers that inspired this work
- Open-source community for tools and libraries
- Academic advisors and mentors for guidance

## 📞 Contact

For questions, collaborations, or technical discussions:
- 📧 Email: bhargavrajdutta685@gmail.com
  



⭐ If you find this project helpful, please consider giving it a star!
