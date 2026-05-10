export function verifyEmailTemplate(link, email) {
  return `
  <!DOCTYPE html>
  <html lang="ru">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  </head>

  <body
    style="
      margin:0;
      padding:0;
      background:#f5f5f5;
      font-family:Arial, sans-serif;
    "
  >

    <table
      width="100%"
      cellpadding="0"
      cellspacing="0"
      border="0"
      style="padding:40px 16px;"
    >
      <tr>
        <td align="center">

          <!-- CARD -->
          <table
            width="100%"
            cellpadding="0"
            cellspacing="0"
            border="0"
            style="
              max-width:420px;
              background:#111111;
              border-radius:24px;
              border:1px solid rgba(255,255,255,0.05);
              overflow:hidden;
              box-shadow:0 10px 40px rgba(0,0,0,0.35);
            "
          >

            <!-- LOGO -->
            <tr>
              <td
                align="center"
                style="
                  padding-top:38px;
                  padding-bottom:10px;
                "
              >

                <img
                  src="https://dizain.pro/logo_3.png"
                  width="35"
                  height="35"
                  alt="dizAIn"
                  style="display:block;"
                />

              </td>
            </tr>

            <!-- TITLE -->
            <tr>
              <td
                align="center"
                style="
                  color:white;
                  font-size:28px;
                  font-weight:500;
                  padding:10px 32px 0 32px;
                "
              >
                Подтверждение почты
              </td>
            </tr>

            <!-- TEXT -->
            <tr>
              <td
                align="center"
                style="
                  color:#aaaaaa;
                  font-size:15px;
                  line-height:1.7;
                  padding:24px 36px 0 36px;
                "
              >

                Здравствуйте, ${email}!<br /><br />

                Нажмите кнопку ниже чтобы подтвердить e-mail
                и войти в сервис.

              </td>
            </tr>

            <!-- BUTTON -->
            <tr>
              <td
                align="center"
                style="
                  padding:34px 32px 18px 32px;
                "
              >

                <a
                  href="${link}"
                  style="
                    display:inline-block;
                    background:white;
                    color:black;
                    text-decoration:none;
                    padding:16px 34px;
                    border-radius:999px;
                    font-size:15px;
                    font-weight:500;
                  "
                >
                  Подтвердить почту
                </a>

              </td>
            </tr>

            <!-- EXPIRES -->
            <tr>
              <td
                align="center"
                style="
                  color:#777777;
                  font-size:13px;
                  padding:4px 32px 0 32px;
                "
              >
                Ссылка действительна 24 часа.
              </td>
            </tr>

            <!-- FOOTER -->
            <tr>
              <td
                align="center"
                style="
                  color:#666666;
                  font-size:12px;
                  line-height:1.6;
                  padding:42px 28px 38px 28px;
                "
              >
                Это письмо было отправлено на ${email}
                по вашей просьбе. Если это были не вы просто проигнорируйте это сообщение.
              </td>
            </tr>

          </table>

        </td>
      </tr>
    </table>

  </body>
  </html>
  `;
}