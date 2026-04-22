import streamlit as st
import pandas as pd
import re
from collections import Counter
from urllib.parse import urlparse, parse_qs

# Configuración de la página
st.set_page_config(page_title="Herramientas de Afiliación", layout="wide")

st.title("🛠️ Suite de Herramientas para Afiliados")

# Función para convertir dataframe a CSV descargable
def convert_df(df):
    return df.to_csv(index=False).encode('utf-8')

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
# PESTAÑA 1: ANALIZADOR DE URLS
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
    uploaded_csvs = st.file_uploader("Sube tus CSVs aquí", type=["csv"], accept_multiple_files=True, key="multi_csv_uploader")
    if uploaded_csvs:
        try:
            dataframes = [pd.read_csv(file) for file in uploaded_csvs]
            df_master = pd.concat(dataframes, ignore_index=True)
            st.success(f"✅ Fusionados {len(uploaded_csvs)} archivos.")
            
            col_ip = find_col(df_master, ['ip', 'ip address', 'ip_address'])
            col_os = find_col(df_master, ['os', 'platform', 'operating system'])
            col_country = find_col(df_master, ['country', 'country code', 'country_code', 'país', 'pais'])
            col_adset = find_col(df_master, ['adset_id', 'adset id', 'adset_name', 'adset name', 'ad group id', 'adgroup_id'])

            if col_adset and col_country:
                st.subheader("🎯 Adset IDs por País")
                adset_country_df = df_master.groupby([col_country, col_adset]).size().reset_index(name='Frecuencia')
                st.dataframe(adset_country_df, use_container_width=True)
            
            if col_ip and col_os and col_country:
                st.divider()
                st.subheader("📊 IPs Únicas")
                df_clean = df_master.dropna(subset=[col_ip, col_os, col_country]).copy()
                grouped = df_clean.groupby([col_country, col_os])[col_ip].unique().reset_index()
                grouped['Total IPs Únicas'] = grouped[col_ip].apply(len)
                grouped['Lista de IPs'] = grouped[col_ip].apply(lambda ips: ", ".join(map(str, ips)))
                st.dataframe(grouped[[col_country, col_os, 'Total IPs Únicas', 'Lista de IPs']], use_container_width=True)
        except Exception as e: st.error(f"Error: {e}")

# ==========================================
# PESTAÑA 3: ANALIZADOR MUNIMOB (CON DESCARGAS)
# ==========================================
with tab3:
    st.header("📱 Analizador Munimob (af_ip)")
    uploaded_munimob = st.file_uploader("Sube tus archivos CSV de Munimob", type=["csv"], accept_multiple_files=True, key="munimob_uploader")
    
    if uploaded_munimob:
        try:
            df_munimob = pd.concat([pd.read_csv(f) for f in uploaded_munimob], ignore_index=True)
            st.success(f"✅ Procesados {len(df_munimob)} registros.")
            col_orig = find_col(df_munimob, ['original url', 'original_url'])
            
            if col_orig:
                all_params_pairs = []
                param_names = set()
                extracted_af_ips = []
                
                for url in df_munimob[col_orig].fillna('').astype(str):
                    params = parse_qs(urlparse(url).query)
                    for key, values in params.items():
                        param_names.add(key)
                        for val in values: all_params_pairs.append({"Parámetro": key, "Valor": val})
                    extracted_af_ips.append(params['af_ip'][0] if 'af_ip' in params else None)
                
                df_munimob['AF_IP_Extraida'] = extracted_af_ips
                
                # --- TABLAS DE PARÁMETROS ---
                st.subheader("1. Parámetros Únicos detectados")
                df_unique_names = pd.DataFrame(sorted(list(param_names)), columns=["Nombre del Parámetro"])
                df_unique_pairs = pd.DataFrame(all_params_pairs).drop_duplicates().sort_values(by="Parámetro")
                
                c1, c2 = st.columns(2)
                with c1:
                    st.write("**Nombres de Parámetros:**")
                    st.dataframe(df_unique_names, use_container_width=True)
                    st.download_button("⬇️ Descargar Nombres", data=convert_df(df_unique_names), file_name="nombres_parametros.csv", mime="text/csv")
                with c2:
                    st.write("**Valores Únicos:**")
                    st.dataframe(df_unique_pairs.reset_index(drop=True), use_container_width=True)
                    st.download_button("⬇️ Descargar Valores", data=convert_df(df_unique_pairs), file_name="valores_parametros.csv", mime="text/csv")

                df_clean_ips = df_munimob.dropna(subset=['AF_IP_Extraida']).copy()
                if not df_clean_ips.empty:
                    # --- LISTA PURA DE IPS ---
                    st.divider()
                    st.subheader("2. Lista limpia de `af_ip` únicas")
                    unique_af_ips = df_clean_ips['AF_IP_Extraida'].unique()
                    df_only_ips = pd.DataFrame(unique_af_ips, columns=['af_ip'])
                    st.dataframe(df_only_ips, use_container_width=True)
                    st.download_button("⬇️ Descargar Lista de IPs Únicas", data=convert_df(df_only_ips), file_name="lista_ips_unicas.csv", mime="text/csv")
                    
                    # --- ALARMAS DE FRAUDE ---
                    st.divider()
                    st.subheader("3. Análisis de Fraude (af_ip >= 5)")
                    col_os_m = find_col(df_clean_ips, ['os', 'platform'])
                    col_country_m = find_col(df_clean_ips, ['country', 'país'])
                    
                    groupby_cols = []
                    if col_country_m: groupby_cols.append(col_country_m)
                    if col_os_m: groupby_cols.append(col_os_m)
                    groupby_cols.append('AF_IP_Extraida')
                    
                    ip_counts = df_clean_ips.groupby(groupby_cols).size().reset_index(name='Repeticiones')
                    suspicious_ips = ip_counts[ip_counts['Repeticiones'] >= 5].sort_values(by='Repeticiones', ascending=False).reset_index(drop=True)
                    
                    if not suspicious_ips.empty:
                        st.dataframe(suspicious_ips, use_container_width=True)
                        st.download_button("⬇️ Descargar Informe de Fraude", data=convert_df(suspicious_ips), file_name="alertas_fraude_munimob.csv", mime="text/csv")
                    else:
                        st.success("✅ No hay IPs repetidas 5+ veces.")

                # --- INVESTIGADOR ---
                st.divider()
                st.subheader("4. Investigador Forense (`af_ip`)")
                search_af_ip = st.text_input("IP a investigar:")
                if search_af_ip:
                    ip_details = df_munimob[df_munimob['AF_IP_Extraida'].astype(str) == search_af_ip.strip()]
                    if not ip_details.empty:
                        res = ip_details.drop(columns=['AF_IP_Extraida'])
                        st.dataframe(res, use_container_width=True)
                        st.download_button("⬇️ Descargar Historial IP", data=convert_df(res), file_name=f"historial_{search_af_ip}.csv", mime="text/csv")
        except Exception as e: st.error(f"Error: {e}")
