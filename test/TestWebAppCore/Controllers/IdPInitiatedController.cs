using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Util;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens.Saml2;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace TestWebAppCore.Controllers
{
    [AllowAnonymous]
    [Route("IdPInitiated")]
    public class IdPInitiatedController : Controller
    {
        public IActionResult Initiate()
        {
            var serviceProviderRealm = "https://samlmock.dev/";

            var binding = new Saml2PostBinding();
            // binding.RelayState = $"RPID={Uri.EscapeDataString(serviceProviderRealm)}";

            var config = new Saml2Configuration();

            config.Issuer = "https://samlmock.dev/";
            config.SingleSignOnDestination = new Uri("https://samlmock.dev/idp?aud=urn:saml-mock-demo&acs_url=http://localhost:5000/Auth/AssertionConsumerService");
            config.SingleLogoutDestination = new Uri("https://samlmock.dev/idp_logout?callback_url=http://localhost:5000/Logout");
            // config.SigningCertificate = CertificateUtil.Load(Startup.AppEnvironment.MapToPhysicalFilePath("itfoxtec.identity.saml2.testwebappcore_Certificate.pfx"), "!QAZ2wsx");
            // config.SignatureAlgorithm = Saml2SecurityAlgorithms.RsaSha256Signature;
            // config.SignatureValidationCertificate = CertificateUtil.Load(Startup.AppEnvironment.MapToPhysicalFilePath("itfoxtec.identity.saml2.testwebappcore_Certificate.cer"));
            var appliesToAddress = "https://samlmock.dev";

            var response = new Saml2AuthnResponse(config);
            response.Status = Saml2StatusCodes.Success;    
   
            var claimsIdentity = new ClaimsIdentity(CreateClaims());
            response.NameId = new Saml2NameIdentifier(claimsIdentity.Claims.Where(c => c.Type == ClaimTypes.NameIdentifier).Select(c => c.Value).Single(), NameIdentifierFormats.Persistent);
            response.ClaimsIdentity = claimsIdentity;
            var token = response.CreateSecurityToken(appliesToAddress);

            return binding.Bind(response).ToActionResult();
        }

        private IEnumerable<Claim> CreateClaims()
        {
            yield return new Claim(ClaimTypes.NameIdentifier, "some-user-identity");
            yield return new Claim(ClaimTypes.Email, "some-user@domain.com");
        }
    }
}
