import streamlit as st
import pandas as pd
import re
from collections import Counter
from urllib.parse import urlparse, parse_qs

# Configuración de la página
st.set_page_config(page_title="Herramientas de Afiliación", layout="wide")

st.title("🛠️ Suite de Herramientas para Afiliados")

# Crear las TRES pestañas principales
tab1, tab2, tab3 = st.tabs([
    "🔗 Analizador de URLs (1 CSV)", 
    "🌍 Extractor Masivo de IPs", 
    "📱 Analizador Munimob (af_ip)"
])

# Función utilitaria para buscar columnas
def find_col(df, possible_names):
    for col in df.columns:
        if col.strip().lower() in possible_names:
            return col
    return None

# ==========================================
# PESTAÑA 1: ANALIZADOR DE URLS Y TOKENS
# ==========================================
with tab1:
    st.header("Analizador de URLs (Versión Simplificada)")
    uploaded_file = st.file_uploader("Sube un (1) archivo CSV para analizar URLs", type=["csv"], key="url_uploader")
    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            st.subheader("1. Tokens Únicos (Postback URL)")
            col_postback = find_col(df, ["postback url"])
            if col_postback:
                token_pattern = re.compile(r'(\{.*?\}|\[.*?\]|<.*?>)')
                all_tokens = []
                urls_pb = df[col_postback].dropna().astype(str)
                for url in urls_pb:
                    all_tokens.extend(token_pattern.findall(url))
                if all_tokens:
                    token_counts = Counter(all_tokens)
                    df_tokens = pd.DataFrame(token_counts.items(), columns=["Token", "Frecuencia"]).sort_values(by="Frecuencia", ascending=False)
                    c1, c2 = st.columns([1, 2])
                    with c1: st.dataframe(df_tokens[["Token"]].reset_index(drop=True), use_container_width=True)
                    with c2: st.bar_chart(df_tokens.set_index("Token"))
            
            st.divider()
            st.subheader("2. Parámetros Únicos (Original URL)")
            col_original = find_col(df, ["original url"])
            if col_original:
                all_params_pairs = []
                param_names = set()
                urls_orig = df[col_original].dropna().astype(str)
                for url in urls_orig:
                    parsed_url = urlparse(url)
                    params = parse_qs(parsed_url.query)
                    for key, values in params.items():
                        param_names.add(key)
                        for val in values: all_params_pairs.append({"Parámetro": key, "Valor": val})
                if param_names:
                    df_unique_pairs = pd.DataFrame(all_params_pairs).drop_duplicates().sort_values(by="Parámetro")
                    st.dataframe(df_unique_pairs.reset_index(drop=True), use_container_width=True)
        except Exception as e: st.error(f"Error: {e}")

# ==========================================
# PESTAÑA 2: EXTRACTOR MASIVO DE IPS + ADSETS
# ==========================================
with tab2:
    st.header("Extractor y Agrupador de IPs y Adsets")
    st.markdown("Sube múltiples CSVs. El sistema unirá los datos y analizará IPs y Adsets.")
    
    uploaded_csvs = st.file_uploader("Arrastra aquí todos tus CSVs", type=["csv"], accept_multiple_files=True, key="multi_csv_uploader")
    
    if uploaded_csvs:
        try:
            dataframes = [pd.read_csv(file) for file in uploaded_csvs]
            df_master = pd.concat(dataframes, ignore_index=True)
            st.success(f"✅ Fusionados {len(uploaded_csvs)} archivos ({len(df_master)} filas).")
            
            # Buscador de columnas
            col_ip = find_col(df_master, ['ip', 'ip address', 'ip_address'])
            col_os = find_col(df_master, ['os', 'platform', 'operating system'])
            col_country = find_col(df_master, ['country', 'country code', 'country_code', 'país', 'pais'])
            col_adset = find_col(df_master, ['adset_id', 'adset id', 'adset_name', 'adset name', 'ad group id', 'adgroup_id'])

            # --- SECCIÓN ADSETS (NUEVA) ---
            st.divider()
            st.subheader("🎯 Análisis de Adset IDs")
            if col_adset:
                adset_counts = df_master[col_adset].fillna('Sin ID').astype(str).value_counts().reset_index()
                adset_counts.columns = ['ID o Nombre de Adset', 'Frecuencia']
                
                st.write(f"Se han detectado **{len(adset_counts)}** Adsets diferentes.")
                
                ca1, ca2 = st.columns([1, 1])
                with ca1:
                    st.dataframe(adset_counts, use_container_width=True)
                with ca2:
                    st.bar_chart(adset_counts.set_index('ID o Nombre de Adset'))
            else:
                st.info("ℹ️ No se encontró ninguna columna de 'Adset ID' en estos archivos.")

            # --- SECCIÓN IPs ---
            st.divider()
            if col_ip and col_os and col_country:
                df_clean = df_master.dropna(subset=[col_ip, col_os, col_country]).copy()
                
                # Tabla Agrupada
                st.subheader("📊 IPs Únicas por País/OS")
                grouped = df_clean.groupby([col_country, col_os])[col_ip].unique().reset_index()
                grouped['Total IPs Únicas'] = grouped[col_ip].apply(len)
                grouped['Lista de IPs'] = grouped[col_ip].apply(lambda ips: ", ".join(map(str, ips)))
                st.dataframe(grouped[[col_country, col_os, 'Total IPs Únicas', 'Lista de IPs']], use_container_width=True)
                
                # Alertas de repetición
                st.subheader("🚨 IPs más repetidas (>= 5)")
                ip_counts = df_clean.groupby([col_country, col_os, col_ip]).size().reset_index(name='Repeticiones')
                suspicious_ips = ip_counts[ip_counts['Repeticiones'] >= 5].sort_values(by='Repeticiones', ascending=False).reset_index(drop=True)
                if not suspicious_ips.empty:
                    st.dataframe(suspicious_ips, use_container_width=True)
                else:
                    st.success("✅ Sin IPs repetidas 5+ veces.")

                # Investigador
                st.divider()
                st.subheader("🔍 Investigador de IP")
                search_ip = st.text_input("IP a buscar:")
                if search_ip:
                    ip_details = df_master[df_master[col_ip].astype(str).str.strip() == search_ip.strip()]
                    if not ip_details.empty:
                        st.dataframe(ip_details, use_container_width=True)
            else:
                st.warning("Faltan columnas de IP, OS o País para el análisis de red.")
                
        except Exception as e: st.error(f"Error: {e}")

# ==========================================
# PESTAÑA 3: ANALIZADOR MUNIMOB
# ==========================================
with tab3:
    st.header("📱 Analizador Munimob (af_ip)")
    uploaded_munimob = st.file_uploader("CSVs de Munimob", type=["csv"], accept_multiple_files=True, key="muni_upl")
    if uploaded_munimob:
        try:
            df_muni = pd.concat([pd.read_csv(f) for f in uploaded_munimob], ignore_index=True)
            col_orig = find_col(df_muni, ['original url', 'original_url'])
            if col_orig:
                extracted_ips = []
                for url in df_muni[col_orig].fillna('').astype(str):
                    params = parse_qs(urlparse(url).query)
                    extracted_ips.append(params['af_ip'][0] if 'af_ip' in params else None)
                df_muni['AF_IP_Extraida'] = extracted_ips
                
                st.subheader("Lista de af_ip únicas")
                st.dataframe(pd.DataFrame(df_muni['AF_IP_Extraida'].dropna().unique(), columns=['af_ip']), use_container_width=True)
                
                st.subheader("Alertas af_ip (>= 5)")
                muni_counts = df_muni.groupby('AF_IP_Extraida').size().reset_index(name='Reps')
                st.dataframe(muni_counts[muni_counts['Reps'] >= 5].sort_values(by='Reps', ascending=False), use_container_width=True)
        except Exception as e: st.error(f"Error: {e}")
