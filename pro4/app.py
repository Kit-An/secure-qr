from flask import Flask, request, jsonify, send_from_directory
import os
import traceback
import canonicalizer
import qr_generator
import scanner

app = Flask(__name__, static_folder='public', static_url_path='')

@app.route('/')
def index():
    return send_from_directory('public', 'index.html')

@app.route('/status', methods=['GET'])
def status():
    default_key = os.environ.get("SAFE_BROWSING_API_KEY", "")
    return jsonify({
        'status': 'ok',
        'message': 'Backend is running',
        'default_key_available': bool(default_key)
    })

@app.route('/check', methods=['POST'])
def check():
    try:
        data = request.get_json() or {}
        raw_url = data.get('url', '').strip()
        key_mode = data.get('key_mode', 'default')
        user_api_key = data.get('api_key', '').strip()

        if not raw_url:
            return jsonify({'valid': False, 'error': 'Please enter a URL'}), 400

        if not raw_url.startswith(('http://', 'https://')):
            target_url = f"https://{raw_url}"
        else:
            target_url = raw_url

        host, path, query = canonicalizer.canonicalize_url(target_url)
        clean_url = f"https://{host}{path}{query}"

        if key_mode == 'own':
            api_key = user_api_key
        else:
            api_key = os.environ.get("SAFE_BROWSING_API_KEY", "")

        sb_result = None
        if api_key:
            sb_result = scanner.query_google_safe_browsing(clean_url, api_key)

        heuristics = scanner.evaluate_heuristics(clean_url)
        score = heuristics['score']

        if sb_result and sb_result.get('flagged'):
            score += 5

        if score < 2:
            risk_level = "Low"
        elif score < 4:
            risk_level = "Medium"
        else:
            risk_level = "High"

        qr_code_base64 = qr_generator.generate_qr(clean_url)

        return jsonify({
            'valid': True,
            'url': clean_url,
            'risk_level': risk_level,
            'warnings': heuristics['warnings'],
            'safe_browsing': sb_result,
            'qr_base64': qr_code_base64
        })

    except Exception as e:
        print("Error processing /check request:", traceback.format_exc())
        return jsonify({'valid': False, 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
