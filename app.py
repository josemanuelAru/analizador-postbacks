import streamlit as st
import pandas as pd
import re
import requests
from collections import Counter
from urllib.parse import urlparse, parse_qs

# Configuración de la página
st.set_page_config(page_title="Herramientas de Afiliación", layout="wide")

st.title("🛠️ Suite de Herramientas para Afiliados")

# --- FUNCIÓN INTELIGENTE: LEER CSV DE APPSFLYER ---
def load_csv(file):
    file.seek(0)
    lines = file.getvalue().decode('utf-8', errors='ignore').splitlines()
    skip = 0
    sep = ','
    for i, line in enumerate(lines[:5]):
        if ';' in line or ',' in line:
            skip = i
            if line.count(';') > line.count(','):
                sep = ';'
            break
    file.seek(0)
    return pd.read_csv(file, sep=sep, skiprows=skip, on_bad_lines='skip')

# --- FUNCIÓN: OBTENER APPLE ID (idXXXXXXXXX) ---
def get_apple_store_id(app_name):
    if not app_name or str(app_name).strip().lower() in ['sin id', 'nan', 'none', '']:
        return "N/A"
    try:
        url = f"https://itunes.apple.com/search?term={app_name}&entity=software&limit=1"
        response = requests.get(url, timeout=5)
        data = response.json()
        if data['resultCount'] > 0:
            track_id = data['results'][0].get('trackId')
            if track_id:
                return f"id{track_id}"
        return "No encontrado"
    except Exception:
        return "Error de conexión"

# Función utilitaria compartida para buscar columnas
def find_col(df, possible_names):
    for col in df.columns:
        if col.strip().lower() in possible_names:
            return col
    return None

# Crear las SIETE pestañas principales
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "🔗 URLs", 
    "🌍 IPs Masivo", 
    "📱 Munimob",
    "🔀 Cruzado",
    "🔢 Contador IPs",
    "🖱️ Click IDs",
    "🚨 Anti-Fraude CTIT"
])

# ==========================================
# PESTAÑA 1: ANALIZADOR DE URLS Y TEMPLATES
# ==========================================
with tab1:
    st.header("Analizador de URLs y Templates")
    uploaded_file = st.file_uploader("Sube un (1) archivo CSV para analizar", type=["csv"], key="url_uploader")

    if uploaded_file is not None:
        try:
            df = load_csv(uploaded_file)
            col_original = find_col(df, ["original url"])
            
            st.subheader("1. Lector de Templates (Onelink ID)")
            if col_original:
                templates = []
                urls_orig = df[col_original].dropna().astype(str)
                for url in urls_orig:
                    path = url.split('?')[0] 
                    template_id = path.split('/')[-1] 
                    if template_id:
                        templates.append(template_id)
                if templates:
                    template_counts = Counter(templates)
                    df_templates = pd.DataFrame(template_counts.items(), columns=["Template ID", "Frecuencia"]).sort_values(by="Frecuencia", ascending=False)
                    st.write(f"Se han detectado **{len(df_templates)}** Templates diferentes.")
                    c_t1, c_t2 = st.columns([1, 2])
                    with c_t1: st.dataframe(df_templates.reset_index(drop=True), use_container_width=True)
                    with c_t2: st.bar_chart(df_templates.set_index("Template ID"))
                else:
                    st.info("No se pudieron extraer Templates de las URLs.")
            else:
                st.warning("No se encontró la columna 'Original URL'.")

            st.divider()
            st.subheader("2. Tokens Únicos (Postback URL)")
            col_postback = find_col(df, ["postback url"])
            if col_postback:
                token_pattern = re.compile(r'(\{.*?\}|\[.*?\]|<.*?>)')
                all_tokens = []
                for url in df[col_postback].dropna().astype(str):
                    all_tokens.extend(token_pattern.findall(url))
                if all_tokens:
                    token_counts = Counter(all_tokens)
                    df_tokens = pd.DataFrame(token_counts.items(), columns=["Token", "Frecuencia"]).sort_values(by="Frecuencia", ascending=False)
                    c1, c2 = st.columns([1, 2])
                    with c1: st.dataframe(df_tokens[["Token"]].reset_index(drop=True), use_container_width=True)
                    with c2: st.bar_chart(df_tokens.set_index("Token"))
            
            st.divider()
            st.subheader("3. Parámetros Únicos Detectados (Original URL)")
            if col_original:
                all_params_pairs = []
                param_names = set()
                for url in df[col_original].dropna().astype(str):
                    params = parse_qs(urlparse(url).query)
                    for key, values in params.items():
                        param_names.add(key)
                        for val in values: all_params_pairs.append({"Parámetro": key, "Valor": val})
                if param_names:
                    df_unique_names = pd.DataFrame(sorted(list(param_names)), columns=["Nombre del Parámetro"])
                    df_unique_pairs = pd.DataFrame(all_params_pairs).drop_duplicates().sort_values(by="Parámetro")
                    st.write("**Nombres de parámetros:**")
                    st.dataframe(df_unique_names, use_container_width=True)
                    st.write("**Combinaciones de Valor únicas:**")
                    st.dataframe(df_unique_pairs.reset_index(drop=True), use_container_width=True)
        except Exception as e:
            st.error(f"Error procesando el archivo: {e}")

# ==========================================
# PESTAÑA 2: EXTRACTOR MASIVO DE IPS + ADSETS
# ==========================================
with tab2:
    st.header("Extractor y Agrupador de IPs y Adsets")
    uploaded_csvs = st.file_uploader("Arrastra aquí todos tus CSVs", type=["csv"], accept_multiple_files=True, key="multi_csv_uploader")
    
    if uploaded_csvs:
        try:
            df_master = pd.concat([load_csv(file) for file in uploaded_csvs], ignore_index=True)
            st.success(f"✅ Fusionados {len(uploaded_csvs)} archivos.")
            col_ip = find_col(df_master, ['ip', 'ip address', 'ip_address'])
            col_os = find_col(df_master, ['os', 'platform', 'operating system'])
            col_country = find_col(df_master, ['country', 'country code', 'país', 'pais'])
            col_adset = find_col(df_master, ['adset_id', 'adset id', 'adset_name', 'adset name'])

            st.divider()
            if col_adset and col_country:
                st.subheader("🎯 Adset IDs por País")
                adset_country_df = df_master.groupby([col_country, col_adset]).size().reset_index(name='Frecuencia')
                st.dataframe(adset_country_df, use_container_width=True)
                st.download_button("⬇️ Descargar Adsets", data=adset_country_df.to_csv(index=False).encode('utf-8'), file_name="adsets_por_pais.csv", mime="text/csv")

                st.markdown("### 🔍 Obtener Apple IDs Oficiales")
                if st.button("Buscar Apple IDs en App Store"):
                    unique_apps = [app for app in adset_country_df[col_adset].unique() if str(app).strip().lower() not in ['sin id', 'nan', 'none', '']]
                    mapping = {}
                    pb = st.progress(0)
                    for i, app_name in enumerate(unique_apps):
                        mapping[app_name] = get_apple_store_id(app_name)
                        pb.progress((i + 1) / len(unique_apps))
                    adset_enriched_df = adset_country_df.copy()
                    adset_enriched_df['Apple ID'] = adset_enriched_df[col_adset].map(mapping).fillna('N/A')
                    st.dataframe(adset_enriched_df, use_container_width=True)
                    st.download_button("⬇️ Descargar con Apple IDs", data=adset_enriched_df.to_csv(index=False).encode('utf-8'), file_name="adsets_con_apple_ids.csv")

            st.divider()
            if col_ip and col_os and col_country:
                df_clean = df_master.dropna(subset=[col_ip, col_os, col_country]).copy()
                st.subheader("📊 IPs Únicas por País/OS")
                grouped = df_clean.groupby([col_country, col_os])[col_ip].unique().reset_index()
                grouped['Total IPs Únicas'] = grouped[col_ip].apply(len)
                grouped['Lista de IPs'] = grouped[col_ip].apply(lambda ips: ", ".join(map(str, ips)))
                st.dataframe(grouped[[col_country, col_os, 'Total IPs Únicas', 'Lista de IPs']], use_container_width=True)
                
                st.subheader("📊 Frecuencia de todas las IPs")
                ip_counts = df_clean.groupby([col_country, col_os, col_ip]).size().reset_index(name='Repeticiones').sort_values(by='Repeticiones', ascending=False)
                st.dataframe(ip_counts, use_container_width=True)
        except Exception as e: st.error(f"Error: {e}")

# ==========================================
# PESTAÑA 3: ANALIZADOR MUNIMOB
# ==========================================
with tab3:
    st.header("📱 Analizador Munimob (af_ip)")
    uploaded_munimob = st.file_uploader("Sube tus CSVs de Munimob", type=["csv"], accept_multiple_files=True, key="munimob_uploader")
    if uploaded_munimob:
        try:
            df_m = pd.concat([load_csv(f) for f in uploaded_munimob], ignore_index=True)
            col_orig = find_col(df_m, ['original url', 'original_url'])
            if col_orig:
                extracted = []
                for url in df_m[col_orig].fillna('').astype(str):
                    params = parse_qs(urlparse(url).query)
                    extracted.append(params['af_ip'][0] if 'af_ip' in params and len(params['af_ip']) > 0 else None)
                df_m['AF_IP_Extraida'] = extracted
                st.subheader("1. Parámetros Únicos de la URL")
                all_p = []
                for url in df_m[col_orig].fillna('').astype(str):
                    params = parse_qs(urlparse(url).query)
                    for k, v in params.items():
                        for val in v: all_p.append({"Parámetro": k, "Valor": val})
                st.dataframe(pd.DataFrame(all_p).drop_duplicates(), use_container_width=True)
                
                if not df_m['AF_IP_Extraida'].dropna().empty:
                    st.divider()
                    st.subheader("2. Lista de af_ip únicas")
                    st.dataframe(pd.DataFrame(df_m['AF_IP_Extraida'].dropna().unique(), columns=['af_ip']), use_container_width=True)
                    st.subheader("3. Análisis de Fraude (>= 5)")
                    fraud = df_m.groupby(['AF_IP_Extraida']).size().reset_index(name='Repeticiones')
                    st.dataframe(fraud[fraud['Repeticiones'] >= 5].sort_values(by='Repeticiones', ascending=False), use_container_width=True)
        except Exception as e: st.error(f"Error en Munimob: {e}")

# ==========================================
# PESTAÑA 4: ANALIZADOR CRUZADO
# ==========================================
with tab4:
    st.header("🔀 Analizador Cruzado Multidimensional")
    uploaded_cross = st.file_uploader("Sube tus CSVs para análisis cruzado", type=["csv"], accept_multiple_files=True, key="cross_uploader")
    if uploaded_cross:
        try:
            df_cross = pd.concat([load_csv(f) for f in uploaded_cross], ignore_index=True)
            st.subheader("1. Frecuencia individual por columna")
            c1, c2, c3 = st.columns(3)
            for i, col in enumerate(df_cross.columns):
                with [c1, c2, c3][i % 3]:
                    with st.expander(f"📊 {col}"):
                        st.dataframe(df_cross[col].value_counts().reset_index(name='Repeticiones'), use_container_width=True)
            
            st.divider()
            st.subheader("2. Analizador Cruzado (Combinaciones)")
            cols = st.multiselect("Selecciona columnas:", df_cross.columns)
            if cols:
                crossed = df_cross.groupby(cols).size().reset_index(name='Repeticiones').sort_values(by='Repeticiones', ascending=False)
                st.dataframe(crossed, use_container_width=True)
                
                st.divider()
                st.subheader("📋 3. Extraer filas originales")
                selected_vals = {}
                c_cols = st.columns(len(cols))
                for idx, col in enumerate(cols):
                    with c_cols[idx]:
                        selected_vals[col] = st.selectbox(f"Filtrar {col}:", ["(Todos)"] + sorted(df_cross[col].dropna().astype(str).unique()))
                df_final = df_cross.copy()
                applied = False
                for col, val in selected_vals.items():
                    if val != "(Todos)":
                        df_final = df_final[df_final[col].astype(str) == val]
                        applied = True
                if applied:
                    st.dataframe(df_final, use_container_width=True)
                    st.download_button("⬇️ Descargar (CSV)", data=df_final.to_csv(index=False).encode('utf-8'), file_name="combinacion.csv")
        except Exception as e: st.error(f"Error: {e}")

# ==========================================
# PESTAÑA 5: CONTADOR DE IPs + REVENUE
# ==========================================
with tab5:
    st.header("🔢 Contador de IPs y Revenue")
    uploaded_ip_counter = st.file_uploader("Sube tu archivo CSV aquí", type=["csv"], key="ip_counter_uploader")
    if uploaded_ip_counter:
        try:
            df_ip = load_csv(uploaded_ip_counter)
            col_ip = find_col(df_ip, ['ip', 'ip address', 'ip_address'])
            col_rev = find_col(df_ip, ['event revenue usd', 'event_revenue_usd', 'revenue'])
            if col_ip:
                df_clean_ip = df_ip.dropna(subset=[col_ip]).copy()
                if not df_clean_ip.empty:
                    st.success("✅ Archivo procesado correctamente.")
                    c1, c2 = st.columns(2)
                    c1.metric("IPs procesadas", len(df_clean_ip))
                    c2.metric("IPs ÚNICAS", df_clean_ip[col_ip].nunique())
                    
                    if col_rev:
                        df_clean_ip[col_rev] = df_clean_ip[col_rev].astype(str).str.replace(r'[^\d.]', '', regex=True)
                        df_clean_ip[col_rev] = pd.to_numeric(df_clean_ip[col_rev], errors='coerce').fillna(0)
                        ip_stats = df_clean_ip.groupby(col_ip).agg(Repeticiones=(col_ip, 'size'), Total_Revenue=(col_rev, 'sum')).reset_index()
                        ip_stats['Total_Revenue'] = ip_stats['Total_Revenue'].round(2)
                    else:
                        ip_stats = df_clean_ip[col_ip].value_counts().reset_index()
                        ip_stats.columns = ['IP', 'Repeticiones']
                    
                    ip_stats = ip_stats.sort_values(by='Repeticiones', ascending=False).reset_index(drop=True)
                    st.dataframe(ip_stats, use_container_width=True)
                    st.download_button("⬇️ Descargar Reporte", data=ip_stats.to_csv(index=False).encode('utf-8'), file_name="contador_ips_revenue.csv", mime="text/csv")
                else: st.warning("⚠️ Columna de IPs vacía.")
            else: st.error("❌ No se encontró columna de IP.")
        except Exception as e: st.error(f"Error: {e}")

# ==========================================
# PESTAÑA 6: CONTADOR DE CLICK IDs + REVENUE
# ==========================================
with tab6:
    st.header("🖱️ Contador de Click IDs y Revenue")
    uploaded_click = st.file_uploader("Sube tu archivo CSV aquí", type=["csv"], key="click_up")
    if uploaded_click:
        try:
            df_clicks = load_csv(uploaded_click)
            col_orig_url = find_col(df_clicks, ['original url', 'original_url'])
            col_rev_click = find_col(df_clicks, ['event revenue usd', 'event_revenue_usd', 'revenue'])
            if col_orig_url:
                ext_clicks = []
                for url in df_clicks[col_orig_url].fillna('').astype(str):
                    params = parse_qs(urlparse(url).query)
                    if 'clickid' in params: ext_clicks.append(params['clickid'][0])
                    elif 'click_id' in params: ext_clicks.append(params['click_id'][0])
                    else: ext_clicks.append(None)
                
                df_clicks['Click_ID_Extraido'] = ext_clicks
                df_cl_clean = df_clicks.dropna(subset=['Click_ID_Extraido']).copy()
                if not df_cl_clean.empty:
                    st.success("✅ Click IDs extraídos.")
                    c1, c2 = st.columns(2)
                    c1.metric("Clicks Procesados", len(df_cl_clean))
                    c2.metric("Click IDs ÚNICOS", df_cl_clean['Click_ID_Extraido'].nunique())
                    
                    if col_rev_click:
                        df_cl_clean[col_rev_click] = df_cl_clean[col_rev_click].astype(str).str.replace(r'[^\d.]', '', regex=True)
                        df_cl_clean[col_rev_click] = pd.to_numeric(df_cl_clean[col_rev_click], errors='coerce').fillna(0)
                        click_stats = df_cl_clean.groupby('Click_ID_Extraido').agg(Repeticiones=('Click_ID_Extraido', 'size'), Total_Revenue=(col_rev_click, 'sum')).reset_index()
                        click_stats['Total_Revenue'] = click_stats['Total_Revenue'].round(2)
                    else:
                        click_stats = df_cl_clean['Click_ID_Extraido'].value_counts().reset_index()
                        click_stats.columns = ['Click_ID_Extraido', 'Repeticiones']
                    
                    click_stats = click_stats.sort_values(by='Repeticiones', ascending=False).reset_index(drop=True)
                    st.dataframe(click_stats, use_container_width=True)
                    st.download_button("⬇️ Descargar Reporte", data=click_stats.to_csv(index=False).encode('utf-8'), file_name="contador_clickids.csv")
            else: st.error("❌ No se encontró columna 'Original URL'.")
        except Exception as e: st.error(f"Error: {e}")

# ==========================================
# PESTAÑA 7: ANTI-FRAUDE CTIT (NUEVA)
# ==========================================
with tab7:
    st.header("🚨 Detector de Fraude (Install Hijacking / CTIT)")
    st.markdown("Analiza la diferencia de tiempo entre el clic y la instalación para detectar comportamientos no humanos.")
    
    uploaded_ctit = st.file_uploader("Sube tu archivo de AppsFlyer", type=["csv"], key="ctit_up")
    
    if uploaded_ctit:
        try:
            df_ctit = load_csv(uploaded_ctit)
            
            # Buscar las columnas de tiempo
            col_click = find_col(df_ctit, ['attributed touch time'])
            col_install = find_col(df_ctit, ['install time'])
            col_adset = find_col(df_ctit, ['adset_id', 'adset id', 'adset_name', 'adset name'])
            
            if col_click and col_install:
                df_clean_ctit = df_ctit.dropna(subset=[col_click, col_install]).copy()
                
                # Convertir a formato de fecha reconociendo el formato europeo de AppsFlyer (dd-mm-yyyy HH:MM)
                df_clean_ctit['Click_DT'] = pd.to_datetime(df_clean_ctit[col_click], dayfirst=True, errors='coerce')
                df_clean_ctit['Install_DT'] = pd.to_datetime(df_clean_ctit[col_install], dayfirst=True, errors='coerce')
                
                # Eliminar filas donde no se pudo interpretar la fecha
                df_clean_ctit = df_clean_ctit.dropna(subset=['Click_DT', 'Install_DT'])
                
                if not df_clean_ctit.empty:
                    # Calcular el CTIT en segundos
                    df_clean_ctit['CTIT_Segundos'] = (df_clean_ctit['Install_DT'] - df_clean_ctit['Click_DT']).dt.total_seconds()
                    
                    # Filtramos instalaciones sospechosas (CTIT <= 20 segundos)
                    df_fraude = df_clean_ctit[df_clean_ctit['CTIT_Segundos'] <= 20].copy()
                    
                    st.divider()
                    st.subheader("📊 Resumen del Análisis de Tiempo")
                    c1, c2 = st.columns(2)
                    c1.metric("Instalaciones Totales Analizadas", len(df_clean_ctit))
                    c2.metric("🚨 Instalaciones Sospechosas (<20s)", len(df_fraude))
                    
                    if not df_fraude.empty:
                        st.error(f"¡Alerta! Se han detectado {len(df_fraude)} instalaciones con un CTIT extremadamente bajo (posible Install Hijacking).")
                        
                        # Agrupamos por culpable (Adset ID)
                        if col_adset:
                            st.subheader("Culpables por Adset")
                            culpables = df_fraude.groupby(col_adset).size().reset_index(name='Instalaciones_Fraudulentas').sort_values(by='Instalaciones_Fraudulentas', ascending=False)
                            st.dataframe(culpables, use_container_width=True)
                        
                        # Mostramos el desglose
                        st.subheader("Detalle de las Instalaciones Sospechosas")
                        columnas_mostrar = [col_click, col_install, 'CTIT_Segundos']
                        if col_adset: columnas_mostrar.insert(0, col_adset)
                        
                        st.dataframe(df_fraude[columnas_mostrar].sort_values(by='CTIT_Segundos'), use_container_width=True)
                        
                        csv_fraude = df_fraude.to_csv(index=False).encode('utf-8')
                        st.download_button("⬇️ Descargar Reporte de Fraude", data=csv_fraude, file_name="reporte_install_hijacking.csv", mime="text/csv")
                    else:
                        st.success("✅ Todo limpio. No se detectaron instalaciones con un CTIT menor a 20 segundos.")
                else:
                    st.warning("No se pudieron interpretar las fechas del archivo.")
            else:
                st.error("❌ No se encontraron las columnas 'Attributed Touch Time' y 'Install Time' necesarias para el cálculo.")
        except Exception as e:
            st.error(f"Error en el análisis de fraude: {e}")
