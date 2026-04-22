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

# Función utilitaria compartida para buscar columnas
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
            
            # --- SECCIÓN 1: TOKENS EN POSTBACK URL ---
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
            dataframes = [pd.read_csv(file) for file in uploaded_csvs]
            df_master = pd.concat(dataframes, ignore_index=True)
            st.success(f"✅ Se han fusionado {len(uploaded_csvs)} archivos con un total de {len(df_master)} filas.")
            
            col_ip = find_col(df_master, ['ip', 'ip address', 'ip_address'])
            col_os = find_col(df_master, ['os', 'platform', 'operating system'])
            col_country = find_col(df_master, ['country', 'country code', 'country_code', 'país', 'pais'])

            missing_cols = []
            if not col_ip: missing_cols.append("IP")
            if not col_os: missing_cols.append("OS")
            if not col_country: missing_cols.append("País")

            if missing_cols:
                st.error(f"❌ Faltan columnas: {', '.join(missing_cols)}.")
            else:
                df_clean = df_master.dropna(subset=[col_ip, col_os, col_country]).copy()
                
                # IPs Agrupadas Únicas
                grouped = df_clean.groupby([col_country, col_os])[col_ip].unique().reset_index()
                grouped['Total IPs Únicas'] = grouped[col_ip].apply(len)
                grouped['Lista de IPs'] = grouped[col_ip].apply(lambda ips: ", ".join(map(str, ips)))
                
                df_final = grouped[[col_country, col_os, 'Total IPs Únicas', 'Lista de IPs']].sort_values(by=[col_country, col_os]).reset_index(drop=True)
                
                st.subheader("📊 Resultados Agrupados (IPs Únicas)")
                st.dataframe(df_final, use_container_width=True)
                
                # IPs Sospechosas
                st.divider()
                st.subheader("🚨 IPs más repetidas (Posible Fraude)")
                ip_counts = df_clean.groupby([col_country, col_os, col_ip]).size().reset_index(name='Repeticiones')
                suspicious_ips = ip_counts[ip_counts['Repeticiones'] >= 5].sort_values(by='Repeticiones', ascending=False).reset_index(drop=True)
                
                if not suspicious_ips.empty:
                    st.dataframe(suspicious_ips, use_container_width=True)
                else:
                    st.success("✅ No se detectó ninguna IP que se repita 5 veces o más.")
                
                # Buscador
                st.divider()
                st.subheader("🔍 Investigador de IP")
                search_ip = st.text_input("Introduce la dirección IP exacta:")
                if search_ip:
                    clean_search_ip = search_ip.strip()
                    ip_details = df_master[df_master[col_ip].astype(str).str.strip() == clean_search_ip]
                    if not ip_details.empty:
                        st.success(f"✅ Se encontraron **{len(ip_details)} registros**.")
                        st.dataframe(ip_details, use_container_width=True)
                    else:
                        st.warning("⚠️ No se encontró la IP.")
        except Exception as e:
            st.error(f"Error: {e}")

# ==========================================
# PESTAÑA 3: ANALIZADOR MUNIMOB (NUEVO)
# ==========================================
with tab3:
    st.header("📱 Analizador Munimob (Extracción de af_ip)")
    st.markdown("Sube tus CSVs de Munimob. El sistema extraerá los parámetros de la **Original URL**, aislará la **af_ip** y realizará un análisis de fraude con ella.")
    
    uploaded_munimob = st.file_uploader("Sube tus archivos CSV de Munimob", type=["csv"], accept_multiple_files=True, key="munimob_uploader")
    
    if uploaded_munimob:
        try:
            # Unir archivos
            df_munimob = pd.concat([pd.read_csv(f) for f in uploaded_munimob], ignore_index=True)
            st.success(f"✅ Se han procesado {len(uploaded_munimob)} archivos con {len(df_munimob)} filas.")
            
            col_orig = find_col(df_munimob, ['original url', 'original_url'])
            
            if col_orig:
                # --- EXTRACCIÓN DE PARÁMETROS Y AF_IP ---
                all_params_pairs = []
                param_names = set()
                extracted_af_ips = []
                
                urls = df_munimob[col_orig].fillna('').astype(str)
                
                for url in urls:
                    if not url:
                        extracted_af_ips.append(None)
                        continue
                        
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    
                    for key, values in params.items():
                        param_names.add(key)
                        for val in values:
                            all_params_pairs.append({"Parámetro": key, "Valor": val})
                    
                    if 'af_ip' in params and len(params['af_ip']) > 0:
                        extracted_af_ips.append(params['af_ip'][0])
                    else:
                        extracted_af_ips.append(None)
                
                df_munimob['AF_IP_Extraida'] = extracted_af_ips
                
                # --- 1. MOSTRAR PARÁMETROS ---
                st.subheader("1. Parámetros Únicos de la URL")
                df_unique_names = pd.DataFrame(sorted(list(param_names)), columns=["Nombre del Parámetro"])
                df_unique_pairs = pd.DataFrame(all_params_pairs).drop_duplicates().sort_values(by="Parámetro")
                
                col_m1, col_m2 = st.columns(2)
                with col_m1:
                    st.dataframe(df_unique_names, use_container_width=True)
                with col_m2:
                    st.dataframe(df_unique_pairs.reset_index(drop=True), use_container_width=True)

                df_clean_ips = df_munimob.dropna(subset=['AF_IP_Extraida']).copy()
                
                if not df_clean_ips.empty:
                    # --- 2. LISTA PURA DE AF_IP (NUEVO) ---
                    st.divider()
                    st.subheader("2. Lista limpia de `af_ip` únicas")
                    st.markdown("Copia fácilmente todas las IPs extraídas haciendo clic en la cabecera de la tabla.")
                    
                    # Extraer IPs únicas y crear un DataFrame de una sola columna
                    unique_af_ips = df_clean_ips['AF_IP_Extraida'].unique()
                    df_only_ips = pd.DataFrame(unique_af_ips, columns=['af_ip'])
                    
                    st.dataframe(df_only_ips, use_container_width=True)
                    
                    # --- 3. CONTADOR Y ALARMAS DE AF_IP ---
                    st.divider()
                    st.subheader("3. Análisis de Fraude sobre `af_ip`")
                    
                    col_os_m = find_col(df_clean_ips, ['os', 'platform', 'operating system'])
                    col_country_m = find_col(df_clean_ips, ['country', 'country code', 'país', 'pais'])
                    
                    groupby_cols = []
                    if col_country_m: groupby_cols.append(col_country_m)
                    if col_os_m: groupby_cols.append(col_os_m)
                    groupby_cols.append('AF_IP_Extraida')
                    
                    ip_counts = df_clean_ips.groupby(groupby_cols).size().reset_index(name='Repeticiones')
                    suspicious_ips = ip_counts[ip_counts['Repeticiones'] >= 5].sort_values(by='Repeticiones', ascending=False).reset_index(drop=True)
                    
                    st.markdown("Mostrando las `af_ip` que se repiten **5 veces o más**:")
                    if not suspicious_ips.empty:
                        st.dataframe(suspicious_ips, use_container_width=True)
                        csv_susp = suspicious_ips.to_csv(index=False).encode('utf-8')
                        st.download_button("⬇️ Descargar Alertas af_ip", data=csv_susp, file_name="munimob_af_ip_alertas.csv", mime="text/csv")
                    else:
                        st.success("✅ Datos limpios: No hay ninguna `af_ip` que alcance las 5 repeticiones.")
                else:
                    st.info("⚠️ No se encontró el parámetro 'af_ip' dentro de ninguna Original URL de estos archivos.")

                # --- 4. INVESTIGADOR DE AF_IP ---
                st.divider()
                st.subheader("🔍 4. Investigador Forense (`af_ip`)")
                st.markdown("Pega aquí una `af_ip` sospechosa para ver **todas las filas de todos los CSVs** donde aparece escondida.")
                
                search_af_ip = st.text_input("Introduce la af_ip exacta a buscar:")
                
                if search_af_ip:
                    clean_search = search_af_ip.strip()
                    ip_details = df_munimob[df_munimob['AF_IP_Extraida'].astype(str) == clean_search]
                    
                    if not ip_details.empty:
                        display_df = ip_details.drop(columns=['AF_IP_Extraida'])
                        st.success(f"✅ Se encontraron **{len(ip_details)} registros** en los que la URL contiene la af_ip: `{clean_search}`")
                        st.dataframe(display_df, use_container_width=True)
                        
                        csv_det = display_df.to_csv(index=False).encode('utf-8')
                        st.download_button(f"⬇️ Descargar historial de la af_ip {clean_search}", data=csv_det, file_name=f"munimob_reporte_{clean_search}.csv", mime="text/csv")
                    else:
                        st.warning("⚠️ No se encontró esa `af_ip` en los archivos.")

            else:
                st.error("❌ No se encontró la columna 'Original URL' en los archivos de Munimob. Revisa los encabezados.")
                
        except Exception as e:
            st.error(f"Error al analizar Munimob: {e}")
