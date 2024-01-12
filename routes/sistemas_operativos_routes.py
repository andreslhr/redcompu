from flask import render_template

def setup_sistemas_operativos_routes(sistemas_operativos_bp):
    @sistemas_operativos_bp.route('/win_7')
    def windows7():
        return render_template('sistemas_operativos/win_7.html')

    @sistemas_operativos_bp.route('/win_10')
    def windows10():
        return render_template('sistemas_operativos/win_10.html')

    @sistemas_operativos_bp.route('/win_11')
    def windows11():
        return render_template('sistemas_operativos/win_11.html')