import streamlit as st
import pandas as pd
import re
import requests
from collections import Counter
from urllib.parse import urlparse, parse_qs

# Configuración de la página
st.set_page_config(page_title="Herramientas de Afiliación", layout="wide")

st.title("🛠️ Suite de Herramientas para Afiliados")

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

# Crear las CUATRO pestañas principales
tab1, tab2, tab3, tab4 = st.tabs([
    "🔗 Analizador de URLs", 
    "🌍 Extractor Masivo de IPs", 
    "📱 Analizador Munimob (af_ip)",
    "🔀 Analizador Cruzado Multidimensional"
])

# ==========================================
# PESTAÑA 1: ANALIZADOR DE URLS Y TEMPLATES
# ==========================================
with tab1:
    st.header("Analizador de URLs y Templates")
    uploaded_file = st.file_uploader("Sube un (1) archivo CSV para analizar", type=["csv"], key="url_uploader")

    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            col_original = find_col(df, ["original url"])
            
            # --- NUEVA SECCIÓN: LECTOR DE TEMPLATES ---
            st.subheader("1. Lector de Templates (Onelink ID)")
            if col_original:
                templates = []
                urls_orig = df[col_original].dropna().astype(str)
                
                for url in urls_orig:
                    # Extraer lo que hay entre la última / y el ?
                    # Ejemplo: https://impressions.onelink.me/Qq7r?pid=... -> Qq7r
                    path = url.split('?')[0] # Nos quedamos con la parte izquierda del ?
                    template_id = path.split('/')[-1] # Nos quedamos con lo último tras la barra
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
            # --- TOKENS POSTBACK ---
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
            # --- PARÁMETROS URL ---
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
            df_master = pd.concat([pd.read_csv(file) for file in uploaded_csvs], ignore_index=True)
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
            df_m = pd.concat([pd.read_csv(f) for f in uploaded_munimob], ignore_index=True)
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
            df_cross = pd.concat([pd.read_csv(f) for f in uploaded_cross], ignore_index=True)
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
                st.subheader("📋 4. Extraer filas originales")
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
