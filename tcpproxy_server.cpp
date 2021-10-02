//
// tcpproxy_server.cpp
// ~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2007 Arash Partow (http://www.partow.net)
// URL: http://www.partow.net/programming/tcpproxy/index.html
//
// Distributed under the Boost Software License, Version 1.0.
//
//
// Description
// ~~~~~~~~~~~
// The  objective of  the TCP  proxy server  is to  act  as  an
// intermediary  in order  to 'forward'  TCP based  connections
// from external clients onto a singular remote server.
//
// The communication flow in  the direction from the  client to
// the proxy to the server is called the upstream flow, and the
// communication flow in the  direction from the server  to the
// proxy  to  the  client   is  called  the  downstream   flow.
// Furthermore  the   up  and   down  stream   connections  are
// consolidated into a single concept known as a bridge.
//
// In the event  either the downstream  or upstream end  points
// disconnect, the proxy server will proceed to disconnect  the
// other  end  point  and  eventually  destroy  the  associated
// bridge.
//
// The following is a flow and structural diagram depicting the
// various elements  (proxy, server  and client)  and how  they
// connect and interact with each other.

//
//                                    ---> upstream --->           +---------------+
//                                                     +---->------>               |
//                               +-----------+         |           | Remote Server |
//                     +--------->          [x]--->----+  +---<---[x]              |
//                     |         | TCP Proxy |            |        +---------------+
// +-----------+       |  +--<--[x] Server   <-----<------+
// |          [x]--->--+  |      +-----------+
// |  Client   |          |
// |           <-----<----+
// +-----------+
//                <--- downstream <---
//
//


#include <cstdlib>
#include <cstddef>
#include <iostream>
#include <string>

#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/thread/mutex.hpp>

#include "TurboBase64/turbob64.h"


namespace tcp_proxy
{
   namespace ip = boost::asio::ip;

   const unsigned char kKey = 42;

   // Default to false because it's more strict (it will fail if somebody
   // meant to encode).
   bool g_encode = false;

   class bridge : public boost::enable_shared_from_this<bridge>
   {
   public:

      typedef ip::tcp::socket socket_type;
      typedef boost::shared_ptr<bridge> ptr_type;

      bridge(boost::asio::io_service& ios)
      : downstream_socket_(ios),
        upstream_socket_  (ios)
      {}

      socket_type& downstream_socket()
      {
         // Client socket
         return downstream_socket_;
      }

      socket_type& upstream_socket()
      {
         // Remote server socket
         return upstream_socket_;
      }

      socket_type& ciphertext_socket()
      {
         return g_encode ? upstream_socket_ : downstream_socket_;
      }

      socket_type& plaintext_socket()
      {
         return g_encode ? downstream_socket_ : upstream_socket_;
      }

      void start(const std::string& upstream_host, unsigned short upstream_port)
      {
         // Attempt connection to remote server (upstream side)
         upstream_socket_.async_connect(
              ip::tcp::endpoint(
                   boost::asio::ip::address::from_string(upstream_host),
                   upstream_port),
              boost::bind(&bridge::handle_upstream_connect,
                   shared_from_this(),
                   boost::asio::placeholders::error));
      }

      void handle_upstream_connect(const boost::system::error_code& error)
      {
         if (!error)
         {
            boost::asio::async_read_until(
                 ciphertext_socket(),
                 ciphertext_buffer_,
                 b64_terminator,
                 boost::bind(&bridge::handle_ciphertext_read,
                      shared_from_this(),
                      boost::asio::placeholders::error,
                      boost::asio::placeholders::bytes_transferred));

            plaintext_socket().async_read_some(
                 boost::asio::buffer(plaintext_data_,max_data_length),
                 boost::bind(&bridge::handle_plaintext_read,
                      shared_from_this(),
                      boost::asio::placeholders::error,
                      boost::asio::placeholders::bytes_transferred));
         }
         else
            close();
      }

   private:
      static const char b64_terminator = '\n';

      bool encrypt(unsigned char* const data,
                   const size_t length,
                   unsigned char* const processed,
                   size_t& processed_length)
      {
         for (size_t i = 0; i < length; ++i)
         {
            data[i] ^= kKey;
         }
         processed_length = tb64enc(data, length, processed);
         if (processed_length <= 0)
         {
            return false;
         }
         processed[processed_length] = b64_terminator;
         ++processed_length;
         return true;
      }

      bool decrypt(unsigned char* const data,
                   size_t length,
                   unsigned char* const processed,
                   size_t& processed_length)
      {
         if (length == 0)
         {
            return false;
         }
         --length;
         if (data[length] != b64_terminator)
         {
            return false;
         }
         processed_length = tb64dec(data, length, processed);
         if (processed_length <= 0)
         {
            return false;
         }
         for (size_t i = 0; i < processed_length; ++i)
         {
            processed[i] ^= kKey;
         }
         return true;
      }


      /*
         Section A: Remote Server --> Proxy --> Client
         Process data recieved from remote sever then send to client.
      */

      // Read from remote server complete, now send data to client
      void handle_ciphertext_read(const boost::system::error_code& error,
                                  const size_t& bytes_transferred)
      {
         if (!error)
         {
            size_t bytes_to_send;
            if (bytes_transferred > max_encoded_data_length)
            {
               close();
            }
            if (!std::istream(&ciphertext_buffer_).read((char*)ciphertext_data_, bytes_transferred))
            {
               close();
            }
            else if (!decrypt(ciphertext_data_,bytes_transferred,ciphertext_decoded_data_,bytes_to_send))
            {
               close();
            }
            else
            {
               async_write(plaintext_socket(),
                    boost::asio::buffer(ciphertext_decoded_data_,bytes_to_send),
                    boost::bind(&bridge::handle_plaintext_write,
                         shared_from_this(),
                         boost::asio::placeholders::error));
            }
         }
         else
            close();
      }

      // Write to client complete, Async read from remote server
      void handle_plaintext_write(const boost::system::error_code& error)
      {
         if (!error)
         {
            boost::asio::async_read_until(
                 ciphertext_socket(),
                 ciphertext_buffer_,
                 b64_terminator,
                 boost::bind(&bridge::handle_ciphertext_read,
                      shared_from_this(),
                      boost::asio::placeholders::error,
                      boost::asio::placeholders::bytes_transferred));
         }
         else
            close();
      }
      // *** End Of Section A ***


      /*
         Section B: Client --> Proxy --> Remove Server
         Process data recieved from client then write to remove server.
      */

      // Read from client complete, now send data to remote server
      void handle_plaintext_read(const boost::system::error_code& error,
                                 const size_t& bytes_transferred)
      {
         if (!error)
         {
            bool result;
            size_t bytes_to_send;
            result = encrypt(plaintext_data_,bytes_transferred,plaintext_encoded_data_,bytes_to_send);
            if (!result)
            {
               close();
            }
            else
            {
               async_write(ciphertext_socket(),
                     boost::asio::buffer(plaintext_encoded_data_,bytes_to_send),
                     boost::bind(&bridge::handle_ciphertext_write,
                           shared_from_this(),
                           boost::asio::placeholders::error));
            }
         }
         else
            close();
      }

      // Write to remote server complete, Async read from client
      void handle_ciphertext_write(const boost::system::error_code& error)
      {
         if (!error)
         {
            plaintext_socket().async_read_some(
                 boost::asio::buffer(plaintext_data_,max_data_length),
                 boost::bind(&bridge::handle_plaintext_read,
                      shared_from_this(),
                      boost::asio::placeholders::error,
                      boost::asio::placeholders::bytes_transferred));
         }
         else
            close();
      }
      // *** End Of Section B ***

      void close()
      {
         boost::mutex::scoped_lock lock(mutex_);

         if (downstream_socket_.is_open())
         {
            downstream_socket_.close();
         }

         if (upstream_socket_.is_open())
         {
            upstream_socket_.close();
         }
      }

      socket_type downstream_socket_;
      socket_type upstream_socket_;

      enum {
         max_data_length = 8192, //8KB
         max_encoded_data_length = TB64ENCLEN(max_data_length) + 1
      };
      boost::asio::streambuf ciphertext_buffer_;
      unsigned char plaintext_data_[max_data_length];
      unsigned char plaintext_encoded_data_[max_encoded_data_length];
      unsigned char ciphertext_data_[max_encoded_data_length];
      unsigned char ciphertext_decoded_data_[max_data_length];

      boost::mutex mutex_;

   public:

      class acceptor
      {
      public:

         acceptor(boost::asio::io_service& io_service,
                  const std::string& local_host, unsigned short local_port,
                  const std::string& upstream_host, unsigned short upstream_port)
         : io_service_(io_service),
           localhost_address(boost::asio::ip::address_v4::from_string(local_host)),
           acceptor_(io_service_,ip::tcp::endpoint(localhost_address,local_port)),
           upstream_port_(upstream_port),
           upstream_host_(upstream_host)
         {}

         bool accept_connections()
         {
            try
            {
               session_ = boost::shared_ptr<bridge>(new bridge(io_service_));

               acceptor_.async_accept(session_->downstream_socket(),
                    boost::bind(&acceptor::handle_accept,
                         this,
                         boost::asio::placeholders::error));
            }
            catch(std::exception& e)
            {
               std::cerr << "acceptor exception: " << e.what() << std::endl;
               return false;
            }

            return true;
         }

      private:

         void handle_accept(const boost::system::error_code& error)
         {
            if (!error)
            {
               session_->start(upstream_host_,upstream_port_);

               if (!accept_connections())
               {
                  std::cerr << "Failure during call to accept." << std::endl;
               }
            }
            else
            {
               std::cerr << "Error: " << error.message() << std::endl;
            }
         }

         boost::asio::io_service& io_service_;
         ip::address_v4 localhost_address;
         ip::tcp::acceptor acceptor_;
         ptr_type session_;
         unsigned short upstream_port_;
         std::string upstream_host_;
      };

   };
}

void usage()
{
   std::cerr << "usage: tcpproxy_server <local host ip> <local port> <forward host ip> <forward port> (encode|decode)" << std::endl;
   std::exit(1);
}

int main(int argc, char* argv[])
{
   if (argc != 6)
   {
      usage();
   }

   const unsigned short local_port   = static_cast<unsigned short>(::atoi(argv[2]));
   const unsigned short forward_port = static_cast<unsigned short>(::atoi(argv[4]));
   const std::string local_host      = argv[1];
   const std::string forward_host    = argv[3];
   const std::string direction       = argv[5];

   if (direction == "encode")
   {
      tcp_proxy::g_encode = true;
   }
   else if (direction == "decode")
   {
      tcp_proxy::g_encode = false;
   }
   else
   {
      usage();
   }

   boost::asio::io_service ios;

   try
   {
      tcp_proxy::bridge::acceptor acceptor(ios,
                                           local_host, local_port,
                                           forward_host, forward_port);

      acceptor.accept_connections();

      ios.run();
   }
   catch(std::exception& e)
   {
      std::cerr << "Error: " << e.what() << std::endl;
      return 1;
   }

   return 0;
}

/*
 * [Note] On posix systems the tcp proxy server build command is as follows:
 * c++ -pedantic -ansi -Wall -Werror -O3 -o tcpproxy_server tcpproxy_server.cpp -L/usr/lib -lstdc++ -lpthread -lboost_thread -lboost_system
 */
