from flask import Flask, render_template
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from werkzeug.utils import secure_filename
import os
import malware
import malware2
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
    

@app.route('/obfuscated', methods=['POST'])
def upload_file_obfuscated():
    form = UploadForm()
    if form.validate_on_submit():
        file = form.file.data
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        data = malware2.is_packed_or_obfuscated(file_path)
        
        return render_template('result2.html', data=data, filename=filename)


if __name__ == '__main__':
    app.run(debug=True)
