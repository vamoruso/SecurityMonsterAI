// InsecureCSRFHandler.cs
using System;
using System.Web;
using System.Web.UI;

public partial class InsecureCSRFHandler : Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        if (Request.HttpMethod == "POST")
        {
            string action = Request.Form["action"];
            if (action == "delete")
            {
                // 🔴 Nessun controllo su token CSRF
                DeleteUserAccount();
                Response.Write("Account eliminato.");
            }
        }
    }

    private void DeleteUserAccount()
    {
        // Simulazione: eliminazione account
    }
}
