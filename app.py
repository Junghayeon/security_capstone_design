from flask import Flask, render_template
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from werkzeug.utils import secure_filename
import os
import malware
import ipcheck
import portcheck
import mail_send

class UploadForm(FlaskForm):
    file = FileField('Choose a file', validators=[
        FileRequired(),
        FileAllowed(['pcap', 'pcapng', 'js'], 'pcap only!')
    ])

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret key'
app.config['UPLOAD_FOLDER'] = 'uploads'

@app.route('/', methods=['GET'])
def upload_page():
    form = UploadForm()
    return render_template('upload.html', form=form)

@app.route('/malware', methods=['POST'])
def upload_file_pcap():
    form = UploadForm()
    data = dict()
    if form.validate_on_submit():
        file = form.file.data
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        data = malware.pcap_read(file_path)

        result = render_template('result.html', data=data, filename=filename)
        mail_send.send_mail(file_path, result)
        
        return result

@app.route('/ipcheck', methods=['POST'])
def upload_file_pcap2():  # Changed the function name to resolve conflict
    form = UploadForm()
    data = dict()
    if form.validate_on_submit():
        file = form.file.data
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        data = ipcheck.pcap_read(file_path)

        result = render_template('ipresult.html', data=data, filename=filename)
        mail_send.send_mail(file_path, result)
        
        return result
    
@app.route('/portcheck', methods=['POST'])
def upload_file_pcap3():  # Changed the function name to resolve conflict
    form = UploadForm()
    data = dict()
    if form.validate_on_submit():
        file = form.file.data
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        data = portcheck.pcap_read(file_path)

        result = render_template('portresult.html', data=data, filename=filename)
        mail_send.send_mail(file_path, result)
        
        return result

if __name__ == '__main__':
    app.run(debug=True)

