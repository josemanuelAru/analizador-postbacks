import streamlit as st
import pandas as pd
import re
from collections import Counter
from urllib.parse import urlparse, parse_qs

# Configuración de la página
st.set_page_config(page_title="Herramientas de Afiliación", layout="wide")

st.title("🛠️ Suite de Herramientas para Afiliados")

# Crear las dos pestañas principales
tab1, tab2 = st.tabs(["🔗 Analizador de URLs (1 CSV)", "🌍 Extractor Masivo de IPs (Múltiples CSVs)"])

# ==========================================
# PESTAÑA 1: ANALIZADOR DE URLS Y TOKENS
# ==========================================
with tab1:
    st.header("Analizador de URLs (Versión Simplificada)")
    uploaded_file = st.file_uploader("Sube un (1) archivo CSV para analizar URLs", type=["csv"], key="url_uploader")

    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            
            # --- SECCIÓN 1: TOKENS EN POSTBACK URL ---
            st.subheader("1. Tokens Únicos (Postback URL)")
            col_postback = next((c for c in df.columns if c.strip().lower() == "postback url"), None)
            
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
                    with c1:
                        st.dataframe(df_tokens[["Token"]].reset_index(drop=True), use_container_width=True)
                    with c2:
                        st.bar_chart(df_tokens.set_index("Token"))
                else:
                    st.info("No se encontraron tokens.")
            else:
                st.warning("Columna 'Postback Url' no encontrada.")

            # --- SECCIÓN 2: PARÁMETROS ÚNICOS (ORIGINAL URL) ---
            st.divider()
            st.subheader("2. Parámetros Únicos Detectados (Original URL)")
            col_original = next((c for c in df.columns if c.strip().lower() == "original url"), None)
            
            if col_original:
                all_params_pairs = []
                param_names = set()
                urls_orig = df[col_original].dropna().astype(str)
                
                for url in urls_orig:
                    parsed_url = urlparse(url)
                    params = parse_qs(parsed_url.query)
                    for key, values in params.items():
                        param_names.add(key)
                        for val in values:
                            all_params_pairs.append({"Parámetro": key, "Valor": val})
                
                if param_names:
                    df_unique_names = pd.DataFrame(sorted(list(param_names)), columns=["Nombre del Parámetro"])
                    df_unique_pairs = pd.DataFrame(all_params_pairs).drop_duplicates().sort_values(by="Parámetro")
                    
                    st.write("**Nombres de parámetros encontrados (Sin duplicados):**")
                    st.dataframe(df_unique_names, use_container_width=True)
                    
                    st.write("**Combinaciones de Valor únicas:**")
                    st.dataframe(df_unique_pairs.reset_index(drop=True), use_container_width=True)

                    # --- SECCIÓN 3: VALORES ÚNICOS APPSFLYER ---
                    st.divider()
                    st.subheader("3. Filtro Específico AppsFlyer")
                    col_af1, col_af2 = st.columns(2)
                    
                    with col_af1:
                        st.write("**af_xplatform_vt_lookback**")
                        lookback_vals = df_unique_pairs[df_unique_pairs["Parámetro"] == "af_xplatform_vt_lookback"]["Valor"].unique()
                        if len(lookback_vals) > 0:
                            st.table(pd.DataFrame(lookback_vals, columns=["Valores Únicos"]))
                        else:
                            st.info("No detectado.")
                            
                    with col_af2:
                        st.write("**af_pmod_priority**")
                        priority_vals = df_unique_pairs[df_unique_pairs["Parámetro"] == "af_pmod_priority"]["Valor"].unique()
                        if len(priority_vals) > 0:
                            st.table(pd.DataFrame(priority_vals, columns=["Valores Únicos"]))
                        else:
                            st.info("No detectado.")
                else:
                    st.info("No se detectaron parámetros en la Original URL.")
            else:
                st.warning("Columna 'Original URL' no encontrada.")
        except Exception as e:
            st.error(f"Error procesando el archivo: {e}")

# ==========================================
# PESTAÑA 2: EXTRACTOR MASIVO DE IPS
# ==========================================
with tab2:
    st.header("Extractor y Agrupador de IPs")
    st.markdown("Sube **múltiples archivos CSV** al mismo tiempo. El sistema los unirá y agrupará las IPs únicas por País y Sistema Operativo.")
    
    uploaded_csvs = st.file_uploader("Arrastra aquí todos tus CSVs", type=["csv"], accept_multiple_files=True, key="multi_csv_uploader")
    
    if uploaded_csvs:
        try:
            # 1. Unir todos los CSVs en un solo DataFrame
            dataframes = []
            for file in uploaded_csvs:
                df_temp = pd.read_csv(file)
                dataframes.append(df_temp)
            
            df_master = pd.concat(dataframes, ignore_index=True)
            st.success(f"✅ Se han fusionado {len(uploaded_csvs)} archivos con un total de {len(df_master)} filas.")
            
            # 2. Función para encontrar columnas
            def find_col(df, possible_names):
                for col in df.columns:
                    if col.strip().lower() in possible_names:
                        return col
                return None

            col_ip = find_col(df_master, ['ip', 'ip address', 'ip_address'])
            col_os = find_col(df_master, ['os', 'platform', 'operating system'])
            col_country = find_col(df_master, ['country', 'country code', 'country_code', 'país', 'pais'])

            missing_cols = []
            if not col_ip: missing_cols.append("IP")
            if not col_os: missing_cols.append("OS")
            if not col_country: missing_cols.append("País")

            if missing_cols:
                st.error(f"❌ Faltan columnas en los CSVs: {', '.join(missing_cols)}.")
                st.info("Encabezados detectados: " + ", ".join(df_master.columns))
            else:
                df_clean = df_master.dropna(subset=[col_ip, col_os, col_country]).copy()
                
                # --- TABLA 1: IPs Agrupadas Únicas ---
                grouped = df_clean.groupby([col_country, col_os])[col_ip].unique().reset_index()
                grouped['Total IPs Únicas'] = grouped[col_ip].apply(len)
                grouped['Lista de IPs'] = grouped[col_ip].apply(lambda ips: ", ".join(map(str, ips)))
                
                df_final = grouped[[col_country, col_os, 'Total IPs Únicas', 'Lista de IPs']].sort_values(by=[col_country, col_os]).reset_index(drop=True)
                
                st.subheader("📊 Resultados Agrupados (IPs Únicas)")
                st.dataframe(df_final, use_container_width=True)
                
                # --- TABLA 2: IPs Sospechosas (>= 5 repeticiones) ---
                st.divider()
                st.subheader("🚨 IPs más repetidas (Posible Fraude)")
                
                ip_counts = df_clean.groupby([col_country, col_os, col_ip]).size().reset_index(name='Repeticiones')
                suspicious_ips = ip_counts[ip_counts['Repeticiones'] >= 5].sort_values(by='Repeticiones', ascending=False).reset_index(drop=True)
                
                if not suspicious_ips.empty:
                    st.dataframe(suspicious_ips, use_container_width=True)
                else:
                    st.success("✅ No se detectó ninguna IP que se repita 5 veces o más.")
                
                # --- SECCIÓN: BUSCADOR DE DETALLES POR IP ---
                st.divider()
                st.subheader("🔍 Investigador de IP")
                st.markdown("Copia una IP de las tablas de arriba y pégala aquí para ver todos sus datos originales.")
                
                search_ip = st.text_input("Introduce la dirección IP exacta:")
                
                if search_ip:
                    clean_search_ip = search_ip.strip()
                    ip_details = df_master[df_master[col_ip].astype(str).str.strip() == clean_search_ip]
                    
                    if not ip_details.empty:
                        st.success(f"✅ Se encontraron **{len(ip_details)} registros** para la IP: `{clean_search_ip}`")
                        st.dataframe(ip_details, use_container_width=True)
                        
                        csv_ip_details = ip_details.to_csv(index=False).encode('utf-8')
                        st.download_button(
                            label=f"⬇️ Descargar historial de la IP {clean_search_ip}",
                            data=csv_ip_details,
                            file_name=f"reporte_ip_{clean_search_ip}.csv",
                            mime="text/csv",
                        )
                    else:
                        st.warning(f"⚠️ No se encontró la IP `{clean_search_ip}` en los archivos subidos.")
                
        except Exception as e:
            st.error(f"Ocurrió un error al procesar los archivos: {e}")
