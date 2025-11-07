// Vulnerabilità: concatenazione diretta nella query SQL
String username = request.getParameter("user");
String query = "SELECT * FROM users WHERE name = '" + username + "'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);
