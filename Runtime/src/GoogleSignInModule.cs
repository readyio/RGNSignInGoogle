using System;
using System.Collections.Generic;
using Firebase;
using Firebase.Auth;
using Firebase.Extensions;
using Google;
using UnityEngine;

namespace RGN.Modules
{
    public class GoogleSignInModule : IRGNModule
    {
        private IRGNRolesCore rgnCore;
        private string webClientId;

        public GoogleSignInModule(string webClientId)
        {
            this.webClientId = webClientId;
        }

        public void SetRGNCore(IRGNRolesCore rgnCore)
        {
            this.rgnCore = rgnCore;
        }

        public void Init()
        {
            GoogleSignIn.Configuration = new GoogleSignInConfiguration
            {
                WebClientId = webClientId,
                UseGameSignIn = false,
                RequestEmail = true,
                RequestIdToken = true
            };
        }

        public void SignOutFromGoogle()
        {
            OnSignOutGoogle();
            rgnCore.SignOutRGN();
        }

        public void OnSignInGoogle(bool isLink = false)
        {
            Debug.Log($"[GoogleSignInModule]: GOOGLE, login started");

            GoogleSignIn.DefaultInstance.SignIn().ContinueWithOnMainThread(task =>
            {
                if (task.IsCanceled)
                {
                    rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                    return;
                }

                if (task.IsFaulted)
                {
                    using (IEnumerator<Exception> enumerator = task.Exception.InnerExceptions.GetEnumerator())
                    {
                        while (enumerator.MoveNext())
                        {
                            var error = (GoogleSignIn.SignInException) enumerator.Current;
                            Debug.Log("[GoogleSignInModule]: GOOGLE, login ERROR " + error.Status + " " +
                                      error.Message);
                        }
                    }

                    rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                    return;
                }

                Debug.Log($"[GoogleSignInModule]: GOOGLE, login SUCCESS {task.Result.DisplayName}||{task.Result.Email}||{task.Result.IdToken}");

                if (isLink)
                {
                    rgnCore.IsUserCanBeLinked(task.Result.Email).ContinueWithOnMainThread(checkLinkResult =>
                    {
                        if (checkLinkResult.IsCanceled)
                        {
                            SignOutFromGoogle();
                            return;
                        }
                    
                        if (checkLinkResult.IsFaulted)
                        {
                            rgnCore.SignOutRGN();
                            rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                            return;
                        }

                        bool canBeLinked = (bool) checkLinkResult.Result.Data;
                        if (!canBeLinked)
                        {
                            OnSignOutGoogle();
                            rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.AccountAlreadyLinked);
                            return;
                        }
                        
                        LinkGoogleAccountToFirebase(task.Result.IdToken);
                    });
                }
                else
                {
                    SignInWithGoogleOnFirebase(task.Result.IdToken);
                }
            });
        }

        private void LinkGoogleAccountToFirebase(string idToken)
        {
            var credential = rgnCore.readyMasterAuth.googleAuthProvider.GetCredential(idToken, null);

            rgnCore.auth.CurrentUser.LinkAndRetrieveDataWithCredentialAsync(credential).ContinueWithOnMainThread(task => 
            {
                if (task.IsCanceled)
                {
                    OnSignOutGoogle();
                    return;
                }
                
                if (task.IsFaulted)
                {
                    FirebaseAccountLinkException firebaseAccountLinkException = task.Exception.InnerException as FirebaseAccountLinkException;
                    if (firebaseAccountLinkException != null && firebaseAccountLinkException.ErrorCode == (int)AuthError.CredentialAlreadyInUse)
                    {
                        OnSignOutGoogle();
                        rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.AccountAlreadyLinked);
                        return;
                    }

                    FirebaseException firebaseException = task.Exception.InnerException as FirebaseException;
                    if (firebaseException != null && firebaseException.ErrorCode == (int)AuthError.EmailAlreadyInUse)
                    {
                        OnSignOutGoogle();
                        rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.AccountAlreadyLinked);
                        return;
                    }
                    
                    foreach (Exception exception in task.Exception.Flatten().InnerExceptions)
                    {
                        Debug.Log(exception.GetType() + " - " + exception.Message + " - " + exception.Source);
                    }

                    OnSignOutGoogle();
                    rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                    return;
                }

                Debug.Log("[GoogleSignInModule]: LinkWith Google Successful. " + rgnCore.auth.CurrentUser.UserId + " ");
                
                rgnCore.auth.CurrentUser.TokenAsync(false).ContinueWithOnMainThread(taskAuth => 
                {
                    if (taskAuth.IsCanceled)
                    {
                        SignOutFromGoogle();
                        return;
                    }
                    if (taskAuth.IsFaulted)
                    {
                        rgnCore.SignOutRGN();
                        rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                        return;
                    }

                    Debug.Log("[GoogleSignInModule]: GOOGLE, userToken " + taskAuth.Result);
                    
                    rgnCore.LinkWithProviderAsync(false, taskAuth.Result).ContinueWithOnMainThread(taskLink => 
                    {
                        Debug.Log("[GoogleSignInModule]: GOOGLE, linked");
                        
                        rgnCore.SetAuthCompletion(EnumLoginState.Success, EnumLoginError.Ok);
                    });
                });
            });
        }

        private void SignInWithGoogleOnFirebase(string idToken)
        {
            var credential = rgnCore.readyMasterAuth.googleAuthProvider.GetCredential(idToken, null);

            rgnCore.auth.SignInWithCredentialAsync(credential).ContinueWithOnMainThread(task => 
            {
                if (task.IsCanceled)
                {
                    SignOutFromGoogle();
                    return;
                }
                
                if (task.IsFaulted)
                {
                    SignOutFromGoogle();
                    rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                    return;
                }

                Debug.Log("[GoogleSignInModule]: GOOGLE, signed in");
                
                rgnCore.auth.CurrentUser.TokenAsync(false).ContinueWithOnMainThread(taskAuth => 
                {
                    Debug.Log("[GoogleSignInModule]: GOOGLE, userToken " + taskAuth.Result);
                    
                    rgnCore.CreateCustomTokenAsync(taskAuth.Result).ContinueWith(taskCustom => 
                    {
                        Debug.Log("[GoogleSignInModule]: GOOGLE, masterToken " + taskCustom.Result);
                        
                        rgnCore.readyMasterAuth.SignInWithCustomTokenAsync(taskCustom.Result);
                    });
                });
            });
        }

        private static void OnSignOutGoogle()
        {
            GoogleSignIn.DefaultInstance.SignOut();
        }
    }
}