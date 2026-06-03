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

# Crear las SEIS pestañas principales
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "🔗 Analizador URLs", 
    "🌍 Extractor Masivo", 
    "📱 Analizador Munimob",
    "🔀 Analizador Cruzado",
    "🔢 Contador IPs",
    "🖱️ Contador Click IDs"
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
                    with c_t1:
                        st.dataframe(df_templates.reset_index(drop=True), use_container_width=True)
                    with c_t2:
                        st.bar_chart(df_templates.set_index("Template ID"))
                else:
                    st.info("No se pudieron extraer Templates de las URLs.")
            else:
                st.warning("No se encontró la columna 'Original URL' para leer los Templates.")

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
                st.download_button(label="⬇️ Descargar Adsets (CSV)", data=adset_country_df.to_csv(index=False).encode('utf-8'), file_name="adsets_por_pais.csv", mime="text/csv")

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
                    st.download_button(label="⬇️ Descargar con Apple IDs", data=adset_enriched_df.to_csv(index=False).encode('utf-8'), file_name="adsets_con_apple_ids.csv")

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
    st.markdown("Sube un CSV para obtener el total de IPs, sus repeticiones y la suma del **Event Revenue USD**.")
    
    uploaded_ip_counter = st.file_uploader("Sube tu archivo CSV aquí", type=["csv"], key="ip_counter_uploader")
    
    if uploaded_ip_counter:
        try:
            df_ip = load_csv(uploaded_ip_counter)
            
            col_ip = find_col(df_ip, ['ip', 'ip address', 'ip_address'])
            col_rev = find_col(df_ip, ['event revenue usd', 'event_revenue_usd', 'revenue', 'revenue usd'])
            
            if col_ip:
                df_clean_ip = df_ip.dropna(subset=[col_ip]).copy()
                
                if not df_clean_ip.empty:
                    total_ips = len(df_clean_ip)
                    unique_ips = df_clean_ip[col_ip].nunique()
                    
                    st.success("✅ Archivo procesado correctamente.")
                    
                    col1, col2 = st.columns(2)
                    col1.metric("Total de IPs procesadas", total_ips)
                    col2.metric("Total de IPs ÚNICAS diferentes", unique_ips)
                    
                    st.divider()
                    st.subheader("📊 Frecuencia e Ingresos por IP")
                    
                    if col_rev:
                        df_clean_ip[col_rev] = df_clean_ip[col_rev].astype(str).str.replace(r'[^\d.]', '', regex=True)
                        df_clean_ip[col_rev] = pd.to_numeric(df_clean_ip[col_rev], errors='coerce').fillna(0)
                        
                        ip_stats = df_clean_ip.groupby(col_ip).agg(
                            Repeticiones=(col_ip, 'size'),
                            Total_Event_Revenue_USD=(col_rev, 'sum')
                        ).reset_index()
                        
                        ip_stats.rename(columns={col_ip: 'IP'}, inplace=True)
                        ip_stats['Total_Event_Revenue_USD'] = ip_stats['Total_Event_Revenue_USD'].round(2)
                    else:
                        st.info("ℹ️ No se detectó ninguna columna de 'Event Revenue USD'. Mostrando solo contador.")
                        ip_stats = df_clean_ip[col_ip].value_counts().reset_index()
                        ip_stats.columns = ['IP', 'Repeticiones']
                    
                    ip_stats = ip_stats.sort_values(by='Repeticiones', ascending=False).reset_index(drop=True)
                    st.dataframe(ip_stats, use_container_width=True)
                    
                    csv_ips = ip_stats.to_csv(index=False).encode('utf-8')
                    st.download_button(label="⬇️ Descargar Reporte (CSV)", data=csv_ips, file_name="contador_ips.csv", mime="text/csv")
                else:
                    st.warning("⚠️ La columna de IPs está vacía.")
            else:
                st.error("❌ No se encontró la columna de IP.")
        except Exception as e:
            st.error(f"Error procesando el archivo: {e}")

# ==========================================
# PESTAÑA 6: CONTADOR DE CLICK IDs + REVENUE (NUEVA)
# ==========================================
with tab6:
    st.header("🖱️ Contador de Click IDs y Revenue")
    st.markdown("Extrae los **Click IDs** directamente desde la *Original URL* y suma el **Event Revenue USD** generado por cada uno.")
    
    uploaded_click_counter = st.file_uploader("Sube tu archivo CSV aquí", type=["csv"], key="click_counter_uploader")
    
    if uploaded_click_counter:
        try:
            df_clicks = load_csv(uploaded_click_counter)
            
            # Buscamos la columna de Original URL y la de Revenue
            col_orig_url = find_col(df_clicks, ['original url', 'original_url'])
            col_rev_click = find_col(df_clicks, ['event revenue usd', 'event_revenue_usd', 'revenue', 'revenue usd'])
            
            if col_orig_url:
                extracted_clicks = []
                for url in df_clicks[col_orig_url].fillna('').astype(str):
                    params = parse_qs(urlparse(url).query)
                    # Buscamos variaciones del parámetro clickid
                    if 'clickid' in params:
                        extracted_clicks.append(params['clickid'][0])
                    elif 'click_id' in params:
                        extracted_clicks.append(params['click_id'][0])
                    else:
                        extracted_clicks.append(None)
                
                df_clicks['Click_ID_Extraido'] = extracted_clicks
                df_clean_clicks = df_clicks.dropna(subset=['Click_ID_Extraido']).copy()
                
                if not df_clean_clicks.empty:
                    total_clicks = len(df_clean_clicks)
                    unique_clicks = df_clean_clicks['Click_ID_Extraido'].nunique()
                    
                    st.success("✅ Archivo procesado y Click IDs extraídos correctamente.")
                    
                    col1, col2 = st.columns(2)
                    col1.metric("Total de Clicks Procesados", total_clicks)
                    col2.metric("Total de Click IDs ÚNICOS diferentes", unique_clicks)
                    
                    st.divider()
                    st.subheader("📊 Frecuencia e Ingresos por Click ID")
                    
                    if col_rev_click:
                        df_clean_clicks[col_rev_click] = df_clean_clicks[col_rev_click].astype(str).str.replace(r'[^\d.]', '', regex=True)
                        df_clean_clicks[col_rev_click] = pd.to_numeric(df_clean_clicks[col_rev_click], errors='coerce').fillna(0)
                        
                        click_stats = df_clean_clicks.groupby('Click_ID_Extraido').agg(
                            Repeticiones=('Click_ID_Extraido', 'size'),
                            Total_Event_Revenue_USD=(col_rev_click, 'sum')
                        ).reset_index()
                        
                        click_stats.rename(columns={'Click_ID_Extraido': 'Click ID'}, inplace=True)
                        click_stats['Total_Event_Revenue_USD'] = click_stats['Total_Event_Revenue_USD'].round(2)
                    else:
                        st.info("ℹ️ No se detectó columna de 'Event Revenue USD'. Mostrando solo el contador de repeticiones.")
                        click_stats = df_clean_clicks['Click_ID_Extraido'].value_counts().reset_index()
                        click_stats.columns = ['Click ID', 'Repeticiones']
                    
                    click_stats = click_stats.sort_values(by='Repeticiones', ascending=False).reset_index(drop=True)
                    st.dataframe(click_stats, use_container_width=True)
                    
                    csv_click_export = click_stats.to_csv(index=False).encode('utf-8')
                    st.download_button(
                        label="⬇️ Descargar Reporte de Click IDs (CSV)",
                        data=csv_click_export,
                        file_name="contador_click_ids_revenue.csv",
                        mime="text/csv"
                    )
                else:
                    st.warning("⚠️ No se encontró el parámetro 'clickid' dentro de las Original URLs de este archivo.")
            else:
                st.error("❌ No se encontró la columna 'Original URL' (necesaria para extraer los Click IDs).")
                
        except Exception as e:
            st.error(f"Error procesando el archivo: {e}")
