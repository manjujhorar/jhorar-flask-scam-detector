from flask import Flask, render_template, request
app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    result = ""
    if request.method == 'POST':
        email = request.form['email']
        # Simple rule-based check
        if any(x in email.lower() for x in ['joboffer', 'lottery', 'urgent']):
            result = "⚠️ This email may be suspicious!"
        else:
            result = "✅ This email looks safe."
    return f"""
    <h2>JHORAR AI – Scam Detector</h2>
    <form method="post">
        <input type="text" name="email" placeholder="Enter email or domain" />
        <button type="submit">Check</button>
    </form>
    <h3>{result}</h3>
    <p>Founder: Manju Jhorar</p>
    """

if __name__ == '__main__':
    app.run(debug=True)
